// SPDX-License-Identifier: GPL-2.0
/*
 * Check the vhost-user-rpmb daemon against the virtio-rpmb device
 * requirements (virtio 1.2 and 1.3, section 5.12) and against the frames
 * OP-TEE sends through the virtio_rpmb frontend.
 *
 * The daemon's main.c is built into this program. The libvhost-user calls
 * it makes are replaced by the stubs below, so that its request loop,
 * vrpmb_handle_ctrl(), runs unchanged on one virtqueue element at a time.
 * Elements are laid out as virtio_rpmb_route_frames() queues them: the
 * request frames, plus a RESULT_READ frame for program key and data write,
 * in device readable buffers, and the response frames in one device
 * writable buffer.
 *
 * Part A sends requests in the form the specification asks for. Part B
 * replays what OP-TEE 4.11 sends on its first boot with in-kernel RPMB
 * routing, and applies the checks OP-TEE makes on the responses.
 *
 * Usage: backend_spec_check <directory for the flash and key files>
 * Exit status is 0 if every check passes, 1 otherwise.
 */
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/wait.h>

#define main vrpmb_daemon_main
#include "main.c"
#undef main

#define FRAME_SIZE	512
#define MAX_FRAMES	8
#define FLASH_SIZE	(1024 * 1024)
#define NR_BLOCKS	(FLASH_SIZE / 256)

/* Frame layout, request types and results from section 5.12.6 */
struct frame {
	uint8_t stuff[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint8_t write_counter[4];
	uint8_t address[2];
	uint8_t block_count[2];
	uint8_t result[2];
	uint8_t req_resp[2];
};
G_STATIC_ASSERT(sizeof(struct frame) == FRAME_SIZE);

/* The MAC covers data to req_resp of every frame of a message. */
#define MAC_INPUT_SIZE	(FRAME_SIZE - offsetof(struct frame, data))

enum {
	REQ_PROGRAM_KEY		= 0x0001,
	REQ_GET_WRITE_COUNTER	= 0x0002,
	REQ_DATA_WRITE		= 0x0003,
	REQ_DATA_READ		= 0x0004,
	REQ_RESULT_READ		= 0x0005,
	RESP_PROGRAM_KEY	= 0x0100,
	RESP_GET_COUNTER	= 0x0200,
	RESP_DATA_WRITE		= 0x0300,
	RESP_DATA_READ		= 0x0400,
};

enum {
	RES_OK			= 0x0000,
	RES_GENERAL_FAILURE	= 0x0001,
	RES_AUTH_FAILURE	= 0x0002,
	RES_COUNT_FAILURE	= 0x0003,
	RES_ADDR_FAILURE	= 0x0004,
	RES_WRITE_FAILURE	= 0x0005,
	RES_READ_FAILURE	= 0x0006,
	RES_NO_AUTH_KEY		= 0x0007,
};

/* OP-TEE's CFG_RPMB_TESTKEY key */
static const uint8_t test_key[32] = {
	0xD3, 0xEB, 0x3E, 0xC3, 0x6E, 0x33, 0x4C, 0x9F,
	0x98, 0x8C, 0xE2, 0xC0, 0xB8, 0x59, 0x54, 0x61,
	0x0D, 0x2B, 0xCF, 0x86, 0x64, 0x84, 0x4D, 0xF2,
	0xAB, 0x56, 0xE6, 0xC6, 0x1B, 0xB7, 0x01, 0xE4,
};

struct reply {
	int signal;		/* signal that killed the daemon, or 0 */
	unsigned int nr_pushed;	/* times the element was returned */
	unsigned int used_len;
	unsigned int nr_frames;	/* size of the response buffer */
	struct frame frm[MAX_FRAMES];
};

static VuRpmb *rpmb;
static VuVirtqElement *queued;
static unsigned int nr_pushed, pushed_len;
static unsigned int nr_checks, nr_failed, nr_returned, nr_len_ok;
static uint8_t shadow[NR_BLOCKS][256];

/* libvhost-user stubs */
VuVirtq *vu_get_queue(VuDev *dev, int qidx)
{
	static VuVirtq vq;

	return &vq;
}

void *vu_queue_pop(VuDev *dev, VuVirtq *vq, size_t sz)
{
	VuVirtqElement *elem = queued;

	queued = NULL;
	return elem;
}

void vu_queue_push(VuDev *dev, VuVirtq *vq, const VuVirtqElement *elem,
		   unsigned int len)
{
	nr_pushed++;
	pushed_len = len;
}

void vu_queue_notify(VuDev *dev, VuVirtq *vq)
{
}

void vu_set_queue_handler(VuDev *dev, VuVirtq *vq,
			  vu_queue_handler_cb handler)
{
}

const char *vu_request_to_string(unsigned int req)
{
	return "stub";
}

bool vug_init(VugDev *dev, uint16_t max_queues, int socket,
	      vu_panic_cb panic, const VuDevIface *iface)
{
	return false;
}

void vug_deinit(VugDev *dev)
{
}

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	put_be16(p, v >> 16);
	put_be16(p + 2, v);
}

static uint16_t get_be16(const uint8_t *p)
{
	return p[0] << 8 | p[1];
}

static uint32_t get_be32(const uint8_t *p)
{
	return (uint32_t)get_be16(p) << 16 | get_be16(p + 2);
}

static void calc_mac(const struct frame *frm, unsigned int n, uint8_t *mac)
{
	GHmac *hmac = g_hmac_new(G_CHECKSUM_SHA256, test_key,
				 sizeof(test_key));
	gsize len = 32;
	unsigned int i;

	for (i = 0; i < n; i++)
		g_hmac_update(hmac, frm[i].data, MAC_INPUT_SIZE);
	g_hmac_get_digest(hmac, mac, &len);
	g_hmac_unref(hmac);
}

static bool mac_ok(const struct frame *frm, unsigned int n)
{
	uint8_t mac[32];

	calc_mac(frm, n, mac);
	return !memcmp(mac, frm[n - 1].key_mac, sizeof(mac));
}

static void new_nonce(uint8_t *nonce)
{
	static uint8_t seq;
	int i;

	for (i = 0; i < 16; i++)
		nonce[i] = ++seq;
}

/* Set up the device state the way main() does for the given options. */
static void start_daemon(const char *flash, const char *key, bool set)
{
	if (rpmb) {
		munmap(rpmb->flash_map, FLASH_SIZE);
		close(rpmb->flash_fd);
		g_free(rpmb->key);
		g_free(rpmb);
	}
	rpmb = g_new0(VuRpmb, 1);
	key_path = (char *)key;
	key_set = set;
	vrpmb_load_flash_image(rpmb, (char *)flash);
	if (key_path && key_set)
		vrpmb_set_key(rpmb, key_path);
}

static void run_request(const struct frame *req, unsigned int nr_req,
			int rr_count, unsigned int nr_resp, struct reply *rep)
{
	struct frame out[MAX_FRAMES], rr = { 0 };
	struct iovec out_sg[2], in_sg[1];
	VuVirtqElement elem = { 0 };

	memset(rep, 0, sizeof(*rep));
	rep->nr_frames = nr_resp;
	memcpy(out, req, nr_req * sizeof(*req));
	put_be16(rr.req_resp, REQ_RESULT_READ);
	if (rr_count > 0)
		put_be16(rr.block_count, rr_count);

	out_sg[0].iov_base = out;
	out_sg[0].iov_len = nr_req * sizeof(*out);
	out_sg[1].iov_base = &rr;
	out_sg[1].iov_len = sizeof(rr);
	in_sg[0].iov_base = rep->frm;
	in_sg[0].iov_len = nr_resp * sizeof(*rep->frm);
	elem.out_num = rr_count < 0 ? 1 : 2;
	elem.out_sg = out_sg;
	elem.in_num = 1;
	elem.in_sg = in_sg;

	queued = &elem;
	nr_pushed = 0;
	pushed_len = 0;
	vrpmb_handle_ctrl(&rpmb->dev.parent, 0);
	rep->nr_pushed = nr_pushed;
	rep->used_len = pushed_len;
}

/*
 * Queue one request as virtio_rpmb_route_frames() does and run the
 * daemon's request loop on it. @rr_count is the block_count of the
 * RESULT_READ frame appended to the request, or -1 for none. With
 * @isolate the daemon runs in a child process, so that a crash is
 * reported instead of ending the check.
 */
static void request(const struct frame *req, unsigned int nr_req,
		    int rr_count, unsigned int nr_resp, bool isolate,
		    struct reply *rep)
{
	struct reply *shared;
	int status;
	pid_t pid;

	g_assert(nr_req <= MAX_FRAMES && nr_resp <= MAX_FRAMES);
	if (!isolate) {
		run_request(req, nr_req, rr_count, nr_resp, rep);
	} else {
		shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		g_assert(shared != MAP_FAILED);
		fflush(NULL);
		pid = fork();
		g_assert(pid >= 0);
		if (!pid) {
			run_request(req, nr_req, rr_count, nr_resp, shared);
			_exit(0);
		}
		waitpid(pid, &status, 0);
		memcpy(rep, shared, sizeof(*rep));
		munmap(shared, sizeof(*shared));
		rep->signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	}

	if (!rep->signal && rep->nr_pushed) {
		nr_returned++;
		if (rep->used_len == rep->nr_frames * FRAME_SIZE)
			nr_len_ok++;
	}
}

static void program_key_frame(struct frame *f, uint16_t block_count)
{
	memset(f, 0, sizeof(*f));
	memcpy(f->key_mac, test_key, sizeof(test_key));
	put_be16(f->block_count, block_count);
	put_be16(f->req_resp, REQ_PROGRAM_KEY);
}

static void counter_frame(struct frame *f, uint16_t block_count,
			  const uint8_t *nonce)
{
	memset(f, 0, sizeof(*f));
	memcpy(f->nonce, nonce, sizeof(f->nonce));
	put_be16(f->block_count, block_count);
	put_be16(f->req_resp, REQ_GET_WRITE_COUNTER);
}

static void read_frame(struct frame *f, uint16_t address,
		       uint16_t block_count, const uint8_t *nonce)
{
	memset(f, 0, sizeof(*f));
	memcpy(f->nonce, nonce, sizeof(f->nonce));
	put_be16(f->address, address);
	put_be16(f->block_count, block_count);
	put_be16(f->req_resp, REQ_DATA_READ);
}

/* As OP-TEE packs a data write: the MAC of all frames is in the last one. */
static void write_frames(struct frame *f, unsigned int n, uint16_t address,
			 uint32_t counter, uint8_t fill)
{
	unsigned int i;

	memset(f, 0, n * sizeof(*f));
	for (i = 0; i < n; i++) {
		memset(f[i].data, fill + i, sizeof(f[i].data));
		put_be32(f[i].write_counter, counter);
		put_be16(f[i].address, address);
		put_be16(f[i].block_count, n);
		put_be16(f[i].req_resp, REQ_DATA_WRITE);
	}
	calc_mac(f, n, f[n - 1].key_mac);
}

static const struct frame *last(const struct reply *rep)
{
	return &rep->frm[rep->nr_frames - 1];
}

static bool replied(const struct reply *rep)
{
	return !rep->signal && rep->nr_pushed == 1 &&
	       rep->used_len == rep->nr_frames * FRAME_SIZE;
}

static bool result_is(const struct reply *rep, uint16_t res, uint16_t type)
{
	return replied(rep) && get_be16(last(rep)->result) == res &&
	       get_be16(last(rep)->req_resp) == type;
}

static const char *result_name(uint16_t res)
{
	switch (res) {
	case RES_OK: return "OK";
	case RES_GENERAL_FAILURE: return "GENERAL_FAILURE";
	case RES_AUTH_FAILURE: return "AUTH_FAILURE";
	case RES_COUNT_FAILURE: return "COUNT_FAILURE";
	case RES_ADDR_FAILURE: return "ADDR_FAILURE";
	case RES_WRITE_FAILURE: return "WRITE_FAILURE";
	case RES_READ_FAILURE: return "READ_FAILURE";
	case RES_NO_AUTH_KEY: return "NO_AUTH_KEY";
	default: return "unknown";
	}
}

static const char *mac_state(const struct reply *rep)
{
	static const uint8_t none[32];

	if (!memcmp(last(rep)->key_mac, none, sizeof(none)))
		return "no MAC";
	return mac_ok(rep->frm, rep->nr_frames) ? "MAC ok" : "MAC wrong";
}

/* What the device answered, as seen in the last response frame. */
static char *describe(const struct reply *rep)
{
	const struct frame *f = last(rep);

	if (rep->signal)
		return g_strdup_printf("daemon killed by signal %d (%s)",
				       rep->signal, strsignal(rep->signal));
	if (!rep->nr_pushed)
		return g_strdup("request not returned");
	return g_strdup_printf("result %s, req_resp 0x%04x, address %u, counter %u, %s%s",
			       result_name(get_be16(f->result)),
			       get_be16(f->req_resp), get_be16(f->address),
			       get_be32(f->write_counter), mac_state(rep),
			       replied(rep) ? "" : ", wrong used length");
}

static void check(bool ok, const char *where, const char *what,
		  const char *fmt, ...)
{
	va_list ap;

	nr_checks++;
	if (!ok)
		nr_failed++;
	printf("%s %-11s %s: ", ok ? "PASS" : "FAIL", where, what);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static void check_reply(bool ok, const char *where, const char *what,
			const struct reply *rep)
{
	g_autofree char *s = describe(rep);

	check(ok, where, what, "%s", s);
}

static void note(const char *fmt, ...)
{
	va_list ap;

	printf("     ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static bool counter_ok(const struct reply *rep, const uint8_t *nonce)
{
	return result_is(rep, RES_OK, RESP_GET_COUNTER) &&
	       !memcmp(last(rep)->nonce, nonce, 16) && mac_ok(rep->frm, 1);
}

/* The checks OP-TEE's tee_rpmb_resp_unpack_verify() makes on a write. */
static bool write_ok(const struct reply *rep, uint16_t address,
		     uint32_t counter)
{
	return result_is(rep, RES_OK, RESP_DATA_WRITE) &&
	       get_be16(last(rep)->address) == address &&
	       get_be32(last(rep)->write_counter) == counter + 1 &&
	       mac_ok(rep->frm, 1);
}

/* The checks OP-TEE makes on a read, and the data read back. */
static bool read_ok(const struct reply *rep, uint16_t address,
		    const uint8_t *nonce)
{
	unsigned int i;

	if (address + rep->nr_frames > NR_BLOCKS ||
	    !result_is(rep, RES_OK, RESP_DATA_READ) ||
	    get_be16(last(rep)->address) != address ||
	    memcmp(last(rep)->nonce, nonce, 16) ||
	    !mac_ok(rep->frm, rep->nr_frames))
		return false;
	for (i = 0; i < rep->nr_frames; i++)
		if (memcmp(rep->frm[i].data, shadow[address + i], 256))
			return false;
	return true;
}

static uint32_t device_counter(void)
{
	struct frame req;
	struct reply rep;
	uint8_t nonce[16];

	new_nonce(nonce);
	counter_frame(&req, 1, nonce);
	request(&req, 1, -1, 1, false, &rep);
	g_assert(counter_ok(&rep, nonce));
	return get_be32(last(&rep)->write_counter);
}

/* Returns the write counter the request was made with. */
static uint32_t write_blocks(unsigned int n, uint16_t address, uint8_t fill,
			     int rr_count, bool isolate, struct reply *rep)
{
	struct frame req[MAX_FRAMES];
	uint32_t counter = device_counter();
	unsigned int i;

	write_frames(req, n, address, counter, fill);
	request(req, n, rr_count, 1, isolate, rep);
	if (write_ok(rep, address, counter) && address + n <= NR_BLOCKS)
		for (i = 0; i < n; i++)
			memcpy(shadow[address + i], req[i].data, 256);

	return counter;
}

static void read_blocks(uint16_t address, uint16_t block_count,
			unsigned int n, bool isolate, uint8_t *nonce,
			struct reply *rep)
{
	struct frame req;

	new_nonce(nonce);
	read_frame(&req, address, block_count, nonce);
	request(&req, 1, -1, n, isolate, rep);
}

static void create_flash(const char *path)
{
	g_autofree char *zero = g_malloc0(FLASH_SIZE);

	g_assert(g_file_set_contents(path, zero, FLASH_SIZE, NULL));
}

static void part_a(const char *dir)
{
	g_autofree char *flash = g_build_filename(dir, "a-flash.img", NULL);
	g_autofree char *key = g_build_filename(dir, "a-key.bin", NULL);
	g_autofree char *saved = NULL;
	unsigned int max_wr, max_rd;
	struct frame req[MAX_FRAMES];
	struct reply rep;
	uint8_t nonce[16], cfg[3], cfg4[4];
	uint32_t counter;
	gsize len = 0;
	bool ok;

	printf("Part A: requests in the form section 5.12 asks for\n");
	create_flash(flash);
	unlink(key);
	memset(shadow, 0, sizeof(shadow));
	start_daemon(flash, key, false);

	ok = !vrpmb_get_config(&rpmb->dev.parent, cfg, sizeof(cfg));
	check(ok && cfg[0] && cfg[0] <= 0x80, "5.12.4", "config space",
	      "%zu bytes: capacity %u x 128 KiB, max_wr_cnt %u, max_rd_cnt %u",
	      sizeof(cfg), cfg[0], cfg[1], cfg[2]);
	max_wr = cfg[1];
	max_rd = cfg[2];
	if (vrpmb_get_config(&rpmb->dev.parent, cfg4, sizeof(cfg4)))
		note("a 4 byte config read is refused: QEMU needs config_size=3");

	new_nonce(nonce);
	counter_frame(req, 1, nonce);
	request(req, 1, -1, 1, false, &rep);
	check_reply(result_is(&rep, RES_NO_AUTH_KEY, RESP_GET_COUNTER),
		    "5.12.6.1.2", "get write counter, no key yet", &rep);

	program_key_frame(req, 0);
	request(req, 1, 1, 1, false, &rep);
	check_reply(result_is(&rep, RES_GENERAL_FAILURE, RESP_PROGRAM_KEY),
		    "5.12.6.1.1", "program key, block_count 0", &rep);

	program_key_frame(req, 1);
	request(req, 1, 1, 1, false, &rep);
	check_reply(result_is(&rep, RES_OK, RESP_PROGRAM_KEY),
		    "5.12.6.1.1", "program key, block_count 1", &rep);

	ok = g_file_get_contents(key, &saved, &len, NULL) && len == 32 &&
	     !memcmp(saved, test_key, 32);
	check(ok, "5.12.6.3", "key file", "%s",
	      ok ? "holds the programmed key" : "does not hold the key");

	program_key_frame(req, 1);
	req[0].key_mac[0] ^= 0xff;
	request(req, 1, 1, 1, false, &rep);
	check_reply(result_is(&rep, RES_WRITE_FAILURE, RESP_PROGRAM_KEY),
		    "5.12.6.1.1", "program a second key", &rep);

	new_nonce(nonce);
	counter_frame(req, 1, nonce);
	request(req, 1, -1, 1, false, &rep);
	check_reply(counter_ok(&rep, nonce) &&
		    !get_be32(last(&rep)->write_counter),
		    "5.12.6.1.2", "get write counter, block_count 1", &rep);

	new_nonce(nonce);
	counter_frame(req, 0, nonce);
	request(req, 1, -1, 1, false, &rep);
	check_reply(result_is(&rep, RES_GENERAL_FAILURE, RESP_GET_COUNTER),
		    "5.12.6.1.2", "get write counter, block_count 0", &rep);

	counter = write_blocks(1, 0, 0x10, 1, false, &rep);
	check_reply(write_ok(&rep, 0, counter), "5.12.6.1.3",
		    "write 1 block at address 0", &rep);

	counter = write_blocks(1, 16, 0x20, 1, false, &rep);
	check_reply(write_ok(&rep, 16, counter), "5.12.6.1.3",
		    "write 1 block at address 16", &rep);

	counter = write_blocks(1, 2, 0x30, 1, false, &rep);
	check_reply(write_ok(&rep, 2, counter), "5.12.6.1.3",
		    "write 1 block at address 2", &rep);

	counter = write_blocks(2, 32, 0x40, 1, false, &rep);
	check_reply(write_ok(&rep, 32, counter), "5.12.6.1.3",
		    "write 2 blocks at address 32", &rep);

	if (max_wr && max_wr < MAX_FRAMES) {
		write_blocks(max_wr + 1, 48, 0x50, 1, false, &rep);
		check_reply(result_is(&rep, RES_GENERAL_FAILURE,
				      RESP_DATA_WRITE),
			    "5.12.6.1.3", "write max_wr_cnt + 1 blocks", &rep);
	}

	write_blocks(1, NR_BLOCKS, 0x60, 1, true, &rep);
	check_reply(result_is(&rep, RES_ADDR_FAILURE, RESP_DATA_WRITE),
		    "5.12.6.1.3", "write 1 block at the first address past the end",
		    &rep);

	write_blocks(1, 64, 0x70, 0, false, &rep);
	check_reply(result_is(&rep, RES_GENERAL_FAILURE, RESP_DATA_WRITE),
		    "5.12.6.1.5", "result read, block_count 0", &rep);

	read_blocks(0, 1, 1, false, nonce, &rep);
	check_reply(read_ok(&rep, 0, nonce), "5.12.6.1.4",
		    "read 1 block at address 0", &rep);

	read_blocks(16, 1, 1, false, nonce, &rep);
	check_reply(read_ok(&rep, 16, nonce), "5.12.6.1.4",
		    "read 1 block at address 16", &rep);

	read_blocks(0, 2, 2, false, nonce, &rep);
	check_reply(read_ok(&rep, 0, nonce), "5.12.6.1.4",
		    "read 2 blocks at address 0", &rep);

	read_blocks(0, 0, 1, true, nonce, &rep);
	check_reply(result_is(&rep, RES_GENERAL_FAILURE, RESP_DATA_READ),
		    "5.12.6.1.4", "read, block_count 0", &rep);

	if (max_rd && max_rd < MAX_FRAMES) {
		read_blocks(0, max_rd + 1, max_rd + 1, false, nonce, &rep);
		check_reply(result_is(&rep, RES_GENERAL_FAILURE,
				      RESP_DATA_READ),
			    "5.12.6.1.4", "read max_rd_cnt + 1 blocks", &rep);
	}

	read_blocks(NR_BLOCKS, 1, 1, true, nonce, &rep);
	check_reply(result_is(&rep, RES_ADDR_FAILURE, RESP_DATA_READ),
		    "5.12.6.1.4", "read 1 block at the first address past the end",
		    &rep);

	counter = device_counter();
	start_daemon(flash, key, true);
	new_nonce(nonce);
	counter_frame(req, 1, nonce);
	request(req, 1, -1, 1, false, &rep);
	check_reply(counter_ok(&rep, nonce), "5.12.6.3",
		    "key after a daemon restart with --key-set", &rep);
	check(counter_ok(&rep, nonce) &&
	      get_be32(last(&rep)->write_counter) == counter, "5.12.6.3",
	      "write counter after a daemon restart", "%u before, %u after",
	      counter, get_be32(last(&rep)->write_counter));
	read_blocks(0, 1, 1, false, nonce, &rep);
	check_reply(read_ok(&rep, 0, nonce), "5.12.6.3",
		    "data after a daemon restart", &rep);

	start_daemon(flash, key, false);
	new_nonce(nonce);
	counter_frame(req, 1, nonce);
	request(req, 1, -1, 1, false, &rep);
	check_reply(counter_ok(&rep, nonce), "5.12.6.3",
		    "key after a daemon restart without --key-set", &rep);
}

/*
 * OP-TEE 4.11 on its first boot, with the frames packed by
 * tee_rpmb_req_pack() and forwarded unchanged by the kernel and by
 * virtio_rpmb_route_frames(). OP-TEE leaves block_count 0 in every
 * request but data write, and gives the length of a read only by the
 * size of the response buffer. Without CFG_RPMB_DRIVER_MULTIPLE_WRITE_FIXED
 * it writes one block at a time.
 */
static void part_b(const char *dir)
{
	g_autofree char *flash = g_build_filename(dir, "b-flash.img", NULL);
	g_autofree char *key = g_build_filename(dir, "b-key.bin", NULL);
	struct frame req;
	struct reply rep;
	uint8_t nonce[16];
	uint32_t counter;

	printf("Part B: OP-TEE 4.11 first boot through virtio_rpmb\n");
	create_flash(flash);
	unlink(key);
	memset(shadow, 0, sizeof(shadow));
	start_daemon(flash, key, false);

	new_nonce(nonce);
	counter_frame(&req, 0, nonce);
	request(&req, 1, -1, 1, false, &rep);
	check_reply(get_be16(last(&rep)->result) == RES_NO_AUTH_KEY &&
		    replied(&rep), "OP-TEE", "get write counter, no key yet",
		    &rep);

	program_key_frame(&req, 0);
	request(&req, 1, 0, 1, false, &rep);
	check_reply(result_is(&rep, RES_OK, RESP_PROGRAM_KEY), "OP-TEE",
		    "program the key", &rep);

	if (!result_is(&rep, RES_OK, RESP_PROGRAM_KEY)) {
		program_key_frame(&req, 1);
		request(&req, 1, 1, 1, false, &rep);
		g_assert(result_is(&rep, RES_OK, RESP_PROGRAM_KEY));
		note("the key is now programmed with block_count 1 to go on");
	}

	new_nonce(nonce);
	counter_frame(&req, 0, nonce);
	request(&req, 1, -1, 1, false, &rep);
	check_reply(counter_ok(&rep, nonce), "OP-TEE", "get write counter",
		    &rep);

	/* rpmb_fs_setup() on an empty device */
	read_blocks(0, 0, 1, true, nonce, &rep);
	check_reply(read_ok(&rep, 0, nonce), "OP-TEE",
		    "read the partition data, 1 block at address 0", &rep);

	counter = write_blocks(1, 0, 0x80, 0, false, &rep);
	check_reply(write_ok(&rep, 0, counter), "OP-TEE",
		    "write the partition data, 1 block at address 0", &rep);

	counter = write_blocks(1, 2, 0x90, 0, false, &rep);
	check_reply(write_ok(&rep, 2, counter), "OP-TEE",
		    "write the first FAT entry, 1 block at address 2", &rep);

	/* fat_entry_dir_init() reads CFG_RPMB_FS_RD_ENTRIES (8) at a time */
	read_blocks(2, 0, 8, true, nonce, &rep);
	check_reply(read_ok(&rep, 2, nonce), "OP-TEE",
		    "read 8 FAT entries, 8 blocks at address 2", &rep);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <work directory>\n", argv[0]);
		return 2;
	}

	part_a(argv[1]);
	part_b(argv[1]);
	check(nr_returned == nr_len_ok, "2.7.8", "used length",
	      "equals the response size in %u of %u returned requests",
	      nr_len_ok, nr_returned);
	printf("%u checks, %u failed\n", nr_checks, nr_failed);

	return nr_failed ? 1 : 0;
}
