/* v90d - the dial-up server daemon (Linux).
 *
 *   v90d [-c FILE] -l LINE [-l LINE2] [-d N] [-i LAN-IF] [-t TUN] [-L LED-PREFIX] [-v]
 *   v90d [-c FILE] -p          print the LAN settings for the boot script
 *
 *   -c FILE    configuration file            [/etc/v90d.conf]
 *   -l LINE    telephone line, see line.h    (required unless -p). Given
 *              twice: the box's two ports; the second one runs on the
 *              [modem2] / [line2] settings and hands out ppp_peer2
 *   -d N       the line's echo bulk delay in samples, if the driver knows it
 *              (see line.h)                  [measured in every V.90 call]
 *   -i LAN-IF  LAN interface: the status and settings pages are served on
 *              its address only              [eth0]
 *   -t TUN     name of the PPP-side network device [ppp0]; the second
 *              port's is the same name with the next digit (ppp1)
 *   -v         log at debug level whatever the file says
 *
 * For the bench (none of these is a setting of the box; DESIGN.md "Linear
 * receive"):
 *   -R FORMATS receive format of the line's codec, one letter per port in
 *              the order of the -l options: l = 16-bit linear, c = companded
 *              (G.711, as the driver starts). "l" or "lc" or "ll" ... Only a
 *              dev: line can be linear; what we send is G.711 levels either
 *              way. Without -R a dev: line is asked for linear (measured
 *              on the unit: 2400 to 5300 bit/s more upstream) and stays
 *              companded if its driver cannot; other lines are left alone.
 *   -P CODE    the most downstream power a V.90 / V.92 caller may ask for,
 *              as INFO0d announces it: -0.5 dBm0 less 0.5 dB per step,
 *              1..31                         [23: -12 dBm0]
 *   -w FILE    record port 1's line while it is off hook, one call: per
 *              10 ms block the 80 codewords heard and the 80 sent. With
 *              linear receive the file begins with the 8 octets "V90DLIN1"
 *              and a block is 80 little-endian 16-bit samples heard and
 *              the 80 codewords sent (live/replay reads both kinds)
 *   -W FILE    the same for port 2
 *
 * One loop, clocked by the lines: every 10 ms each line delivers a block of
 * 80 samples, which goes through that port's server core (srv.h) and is
 * answered at once; between blocks IP packets move between the TUN devices
 * and the calls, and the HTTP server gets its turn. Nothing is allocated
 * after start-up and nothing blocks but the wait for the next block. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "srv.h"
#include "httpd.h"
#include "line.h"
#include "tun.h"
#include "nat.h"
#include "dclist.h"
#include "dcnow.h"
#include "upnp.h"
#include "daemon.h"
#include "satlink.h"
#include "bbslink.h"
#include "update.h"
#include "netsvc.h"
#include "vpn.h"
#include "settings.h"

#define PORTS CFG_PORTS
srv_t           S[PORTS];
int             n_ports;
int             heavy_inflight; /* shared heavy-call arbiter: calls now offering x2 or K56flex (one at a time) */
static httpd_t  H;
static cfg_t    live;               /* what the settings page shows and edits */
static const char *cfg_path = "/etc/v90d.conf";
#define RESTART_NOTE "/tmp/v90d.restart"
const char *lan_if = "eth0";
char            tun_name[PORTS][16] = { "ppp0", "ppp1" };
int             tun_fd[PORTS] = { -1, -1 };
static cfg_t    unsaved; static int have_unsaved;   /* saved from the form during a call */
static int      log_level = CFG_LOG_INFO, force_debug;
static volatile sig_atomic_t stop;


/* The Firmware page (cfg/firmware.h). Both things it can do write the flash,
 * and one of them first takes a megabyte from a browser: neither is done
 * here. A request that may go ahead is handed, connection and all, to the
 * flash tool of the image (fw/tools/v90nv, nvhttp.c) as a child of ours.
 * What the page shows comes from two small files in memory: what the boot
 * script noted about how the box was started, and what that child noted
 * about its last write. */
static const char *fw_tool = "/usr/sbin/v90nv";
static const char *fw_update_cmd = "sh /etc/fwupdate.sh";    /* run as CMD VERSION to install an update */
static pid_t    fw_pid;

/* The recent daemon log, kept in memory so the owner can read it on the /log
 * page without a serial console. The newest LOG_RING octets at most, oldest
 * first; whole lines are dropped from the front to make room. */
#define LOG_RING 8192
static char   log_ring[LOG_RING];
static size_t log_ring_len;
static void log_ring_add(const char *s, size_t len)
{
    if (len > LOG_RING) { s += len - LOG_RING; len = LOG_RING; }     /* a line longer than the ring: keep its tail */
    if (log_ring_len + len > LOG_RING) {
        size_t need = log_ring_len + len - LOG_RING, drop = need;
        char *nl = memchr(log_ring + need, '\n', log_ring_len - need);
        if (nl) drop = (size_t)(nl + 1 - log_ring);                  /* drop whole lines, not a fragment */
        memmove(log_ring, log_ring + drop, log_ring_len - drop);
        log_ring_len -= drop;
    }
    memcpy(log_ring + log_ring_len, s, len);
    log_ring_len += len;
}

void logf_(int level, const char *fmt, ...)
{
    static const char *const tag[] = { "error", "warn", "info", "debug" };
    char line[512]; int p, q; va_list ap;
    if (level > log_level) return;
    p = snprintf(line, sizeof line, "v90d %s: ", tag[level]);
    if (p < 0) p = 0;
    if (p > (int)sizeof line - 2) p = (int)sizeof line - 2;
    va_start(ap, fmt);
    q = vsnprintf(line + p, sizeof line - (size_t)p, fmt, ap);
    va_end(ap);
    if (q > 0) p += q;
    if (p > (int)sizeof line - 2) p = (int)sizeof line - 2;          /* truncated: still leave room for \n and NUL */
    line[p++] = '\n';
    line[p] = 0;
    fputs(line, stderr);
    log_ring_add(line, (size_t)p);
}

/* GET /log (httpd_on_diag): the daemon's recent log and the kernel's, as plain
 * text, for the owner to read or save and attach to a bug report. No config
 * secrets are here (that is /config, redacted); any addresses in the log are
 * the owner's own network. */
static int diag_fill(void *ctx, char *buf, size_t cap)
{
    int n, k;
    (void)ctx;
    if (cap == 0) return 0;
    n = snprintf(buf, cap, "v90d %s (built %s)\n\n=== daemon log ===\n", V90D_VERSION, __DATE__);
    if (n < 0) n = 0;
    if ((size_t)n > cap - 1) n = (int)cap - 1;
    if (log_ring_len && (size_t)n + log_ring_len < cap) {
        memcpy(buf + n, log_ring, log_ring_len);
        n += (int)log_ring_len;
    }
    if ((size_t)n < cap - 1) {
        int m = snprintf(buf + n, cap - (size_t)n, "\n=== kernel log ===\n");
        if (m > 0) n += m;
        if ((size_t)n > cap - 1) n = (int)cap - 1;
    }
    if ((size_t)n < cap - 1) {
        k = klogctl(3 /* SYSLOG_ACTION_READ_ALL: the kernel's buffer, left in place */, buf + n, (int)(cap - 1 - (size_t)n));
        if (k > 0) n += k;
    }
    buf[n] = 0;
    return n;
}

const char *ip_str(uint32_t ip, char buf[16])
{
    snprintf(buf, 16, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)(ip >> 16) & 255, (unsigned)(ip >> 8) & 255, (unsigned)ip & 255);
    return buf;
}

static void on_term(int sig) { (void)sig; stop = 1; }

/* an IP packet from the caller: into the kernel */
static void ip_to_kernel(void *ctx, const uint8_t *pkt, size_t len)
{
    int i = (int)(((srv_t *)ctx) - S);
    if (tun_fd[i] >= 0 && write(tun_fd[i], pkt, len) < 0) S[i].status.rx_errors++;
}

/* a port has the archive for its service */

/* a port has the game console service */

/* The address list of the game revival projects (dclist.h): fetched by a
 * child process while a port has the console service. The child writes the
 * list to its standard output, a pipe we read as it comes (no file, so
 * nothing in /tmp to be put in its way); it is parsed when the child is
 * done and in force from the next time the line is idle. A fetch that fails
 * leaves the list as it was. */

/* "Dreamcast Now" (dcnow.h): while the caller of a console port that asks
 * for it has its network up, a report every 15 s, sent by a child process
 * (the image's wget; dn_prog, when set, is run instead as "prog URL BODY"). */

/* A console as a host on the network (dreamcast_lan): the caller of that
 * port gets an address of the network itself. The address comes from a
 * command that prints it (on the box, udhcpc asking the network's DHCP
 * server for a second lease under a client name of its own; the script it
 * is given prints the address and changes nothing). It is asked again every
 * half hour, which also keeps the lease. Without an answer the port stays
 * as the settings have it, behind this box's address. */
/* Game ports from the router (dreamcast_upnp): a child process asks the
 * network's router to pass the ports of dclist.h on, to the console itself
 * when it is a host on the network and to this box otherwise (which passes
 * them on). Asked again whenever the addresses change and every half hour;
 * taken back when the switch goes off and when the daemon stops. */


/* ---- the VPN for the IWANGO games (dreamcast_iwango). The games' servers
 * of today stand in a private network behind an OpenVPN server; the owner
 * of the box has a client profile for it and gives it to the Dreamcast
 * page (cfg/vpn.h checks it). OpenVPN itself is not ours: the image carries
 * the program as it is (DESIGN.md, the owner's decision), and this code
 * only keeps it running while a dreamcast port wants it. ---- */

/* the server a stored profile names, for the page and the log; 0 = no profile */
/* the Dreamcast page was given a profile (len 0: take the stored one away) */

/* the network side answers ARP for the console's address, or not */

static int all_onhook(void)
{
    int i;
    for (i = 0; i < n_ports; i++) if (S[i].tel.state != TEL_ONHOOK) return 0;
    return 1;
}


/* start, stop or restart the gateway as wanted; called on a change and every few seconds */

static int fw_text(void *ctx, int which, char *buf, size_t cap)
{
    const char *path = which == HTTPD_FW_WHERE ? getenv("V90D_WHERE") : getenv("V90NV_STATE");
    ssize_t n = 0;
    int fd;
    (void)ctx;
    if (!path) path = which == HTTPD_FW_WHERE ? "/tmp/v90d.where" : "/tmp/v90d.fwstate";
    buf[0] = '\0';
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) >= 0) {
        n = read(fd, buf, cap - 1);
        close(fd);
        if (n < 0) n = 0;
    }
    buf[n] = '\0';
    /* let the Firmware page see an available update as one more WHERE line */
    if (which == HTTPD_FW_WHERE) {
        char ver[32];
        if (update_available(ver, sizeof ver)) {
            size_t have = (size_t)n;
            if (have && buf[have - 1] != '\n' && have + 1 < cap) buf[have++] = '\n';
            n = (ssize_t)have + snprintf(buf + have, cap - have, "update_avail=%s\n", ver);
            if (n >= (ssize_t)cap) n = (ssize_t)cap - 1;
            buf[n] = '\0';
        }
    }
    return (int)n;
}

static const char *fw_take(void *ctx, int what, int fd, const char *early, size_t early_len, size_t content_length, const char *ctype)
{
    char len[24];
    int pfd[2], i;
    (void)ctx;
    /* flash writes hold the processor in bursts: not under a call */
    if (!all_onhook()) return "A call is in progress. Try again when the lines are free.";
    if (fw_pid > 0 && waitpid(fw_pid, NULL, WNOHANG) == 0) return "The flash is being written already. Wait until that is done.";
    fw_pid = 0;
    /* what we have of the body goes ahead through a pipe (it holds 64 kB,
     * the request buffer is two) */
    if (pipe(pfd) < 0) return "The box cannot start its flash tool just now.";
    if (early_len && write(pfd[1], early, early_len) != (ssize_t)early_len) { close(pfd[0]); close(pfd[1]); return "The box cannot start its flash tool just now."; }
    snprintf(len, sizeof len, "%lu", (unsigned long)content_length);
    fw_pid = fork();
    if (fw_pid == 0) {
        struct sched_param sp;
        memset(&sp, 0, sizeof sp);
        (void)sched_setscheduler(0, SCHED_OTHER, &sp);
        (void)munlockall();
        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(pfd[0], 3) < 0) _exit(127);
        for (i = 4; i < 256; i++) close(i);     /* the lines, the listener: none of its business */
        (void)setenv("V90NV_EARLY_FD", "3", 1);
        execl(fw_tool, fw_tool, what == HTTPD_FW_UPLOAD ? "serve-upgrade" : "serve-stock", len,
              what == HTTPD_FW_UPLOAD ? ctype : (char *)NULL, (char *)NULL);
        _exit(127);
    }
    close(pfd[0]); close(pfd[1]);
    if (fw_pid < 0) { fw_pid = 0; return "The box cannot start its flash tool just now."; }
    logf_(CFG_LOG_INFO, "firmware page: %s handed to %s", what == HTTPD_FW_UPLOAD ? "an upload" : "back to stock", fw_tool);
    return NULL;
}

/* POST /firmware/update: install the release the daily check found. Same
 * guards as an upload. A child fetches our own release image and hands it to
 * the flash tool; the daemon keeps serving while it runs, and the child
 * leaves the restart note when it is done. Its words go to the state file,
 * so the Firmware page's "Last upload" shows how it went. */
static const char *fw_install(void *ctx)
{
    char ver[32], cmd[160];
    int i;
    (void)ctx;
    if (!update_available(ver, sizeof ver)) return "There is no update to install.";
    if (!all_onhook()) return "A call is in progress. Try again when the lines are free.";
    if (fw_pid > 0 && waitpid(fw_pid, NULL, WNOHANG) == 0) return "The flash is being written already. Wait until that is done.";
    fw_pid = 0;
    /* ver is digits and dots only (update_available checks), so the command is safe to build */
    if (snprintf(cmd, sizeof cmd, "%s %s", fw_update_cmd, ver) >= (int)sizeof cmd) return "The box cannot start the update just now.";
    fw_pid = fork();
    if (fw_pid == 0) {
        const char *st = getenv("V90NV_STATE"); int fd;
        struct sched_param sp;
        memset(&sp, 0, sizeof sp);
        (void)sched_setscheduler(0, SCHED_OTHER, &sp);
        (void)munlockall();
        if (!st) st = "/tmp/v90d.fwstate";
        fd = open(st, O_WRONLY | O_CREAT | O_TRUNC, 0600);   /* the script's words land where the page reads them */
        if (fd >= 0) { (void)dup2(fd, 1); (void)dup2(fd, 2); }
        for (i = 3; i < 256; i++) close(i);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    if (fw_pid < 0) { fw_pid = 0; return "The box cannot start the update just now."; }
    logf_(CFG_LOG_INFO, "firmware page: installing update %s with %s", ver, fw_update_cmd);
    return NULL;
}

/* TUN devices, forwarding and NAT as the configuration in force wants them */

/* a new configuration is in force from the next call */
static void adopt(const cfg_t *n)
{
    static cfg_t view;
    int i;
    if (!force_debug) log_level = n->log_level;
    for (i = 0; i < n_ports; i++) {
        cfg_for_port(n, i, &view);
        netsvc_set_peer_conf(i, view.ppp_peer);
        if (view.service == CFG_SERVICE_DREAMCAST && view.dc_lan && netsvc_lan_ip(i)) view.ppp_peer = netsvc_lan_ip(i);
        if (view.dc_lan != S[i].cfg.dc_lan) net_dirty = 1;
        if (view.ppp_local != S[i].cfg.ppp_local || view.ppp_peer != S[i].cfg.ppp_peer || view.nat != S[i].cfg.nat || view.service != S[i].cfg.service || view.mru != S[i].cfg.mru)
            net_dirty = 1;
        srv_reconfigure(&S[i], &view);
    }
    update_config(n->update_check, V90D_VERSION);
}

static int store(const cfg_t *n)
{
    char err[CFG_ERR_MAX];
    if (cfg_save(n, cfg_path, err, sizeof err) != CFG_OK) {
        logf_(CFG_LOG_ERROR, "settings not saved: %s", err);
        return -1;
    }
    logf_(CFG_LOG_INFO, "settings saved to %s; they apply from the next call", cfg_path);
    return 0;
}

/* The settings page was posted. Writing the file can stall for as long as
 * the flash takes, and a call does not survive missing its samples: while
 * the line is in use the file is written after the call. */
static int on_save(void *ctx, const cfg_t *n)
{
    (void)ctx;
    if (!all_onhook()) {
        unsaved = *n; have_unsaved = 1;
        adopt(n);
        logf_(CFG_LOG_INFO, "settings accepted; the file is written when the lines are free");
        return 0;
    }
    if (store(n) != 0) return -1;
    have_unsaved = 0;
    adopt(n);
    return 0;
}

static const char *const tel_name[] = { "answered", "busy", "wrong number", "abandoned", "line dropped", "session limit", "idle timeout" };
static const char *const mod_name[] = { "no carrier", "V.90", "V.34", "V.32bis", "V.22bis", "V.22", "V.21", "V.92", "Bell 103", "Bell 212A" };

/* PPP compression (CCP) of the call that ended: one line, only if it was used */
static void log_ppp_comp(const char *who, const ppp_t *ppp)
{
    static const char *const alg[] = { "none", "Deflate", "MPPC" };
    ppp_status_t ps;
    const ppp_counters_t *k = &ps.counters;
    ppp_get_status(ppp, &ps);
    if (!k->ccp_opens) return;
    logf_(CFG_LOG_INFO, "%s  PPP compression: to caller %s %lu -> %lu octets (%lu packets sent as they were), from caller %s %lu -> %lu;"
          " resets asked of us %lu, by us %lu (%lu packets dropped), CCP opened %lu time(s)",
          who, alg[k->comp_tx < 3 ? k->comp_tx : 0], (unsigned long)k->comp_tx_in, (unsigned long)k->comp_tx_out,
          (unsigned long)k->comp_tx_native, alg[k->comp_rx < 3 ? k->comp_rx : 0],
          (unsigned long)k->comp_rx_in, (unsigned long)k->comp_rx_out,
          (unsigned long)k->comp_tx_resets, (unsigned long)k->comp_rx_errors, (unsigned long)k->comp_rx_dropped,
          (unsigned long)k->ccp_opens);
}

static void log_last_call(int port)
{
    const st_call_t *h = status_call(&S[port].status, 0);
    char who[12] = "";
    if (!h) return;
    if (n_ports > 1) snprintf(who, sizeof who, "port %d: ", port + 1);
    logf_(CFG_LOG_INFO, "%scall to \"%s\": %s; %s %u/%u bit/s, %u s",
          who, h->dialed, (unsigned)h->tel_result < 7 ? tel_name[h->tel_result] : "?",
          (unsigned)h->modulation < sizeof mod_name / sizeof mod_name[0] ? mod_name[h->modulation] : "?",
          (unsigned)h->down_bps, (unsigned)h->up_bps, (unsigned)h->duration_s);
    if (h->modulation) {
        /* the call object is left as it ended: what the link layer did */
        v90m_ec_status v;
        char comp[96];
        v90m_ec_get_status(S[port].dce.v42, &v);
        /* send/receive direction; V.44 has its values per direction */
        if (v.comp_alg == V90M_EC_COMP_V44)
            snprintf(comp, sizeof comp, "V.44 %s/%s %d/%d codewords, string %d/%d, history %d/%d",
                     v.comp_tx ? "on" : "off", v.comp_rx ? "on" : "off", v.v44_n2_tx, v.v44_n2_rx,
                     v.v44_n7_tx, v.v44_n7_rx, v.v44_n8_tx, v.v44_n8_rx);
        else
            snprintf(comp, sizeof comp, "V.42bis %s/%s %d codewords, string %d",
                     v.comp_tx ? "on" : "off", v.comp_rx ? "on" : "off", v.comp_n2, v.comp_n7);
        logf_(CFG_LOG_INFO, "%s  link: k %d/%d, N401 %d/%d, %s; I frames %lu sent (%lu again), %lu received (%lu dropped), REJ %lu sent %lu received, T401 ran out %lu times; compressor %lu -> %lu octets, expander %lu -> %lu",
              who, v.k_tx, v.k_rx, v.n401_tx, v.n401_rx, comp,
              v.tx_i, v.tx_i_retx, v.rx_i, v.rx_i_dropped, v.tx_rej, v.rx_rej, v.t401_expiries, v.comp_in, v.comp_out, v.decomp_in, v.decomp_out);
        log_ppp_comp(who, &S[port].dce.ppp);
    }
}

/* the octets of a call without PPP: a bulletin board call, or the port's saturn service */
static void raw_from_modem(void *ctx, const uint8_t *oct, size_t n)
{
    uint32_t addr; int on;
    if (srv_link((srv_t *)ctx, &addr, &on) == SRV_LINK_BBS) bbslink_from_modem(ctx, oct, n);
    else satlink_from_modem(ctx, oct, n);
}

static void usage(void)
{
    fprintf(stderr, "usage: v90d [-c FILE] -l LINE [-l LINE2] [-d N] [-i LAN-IF] [-t TUN] [-A GATEWAY] [-D FETCH-COMMAND] [-G REPORT-PROGRAM] [-E LEASE-COMMAND] [-v]\n       v90d [-c FILE] -p\n"
                    "bench: [-R l|c per port, e.g. lc] [-P 1..31: maximum downstream power code] [-w|-W FILE: record port 1|2]\n"
                    "       [-o: the box calls a modem that goes off hook (told ATA): V.34, V.32bis, V.22bis, V.22, V.21]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    static uint8_t pending[PORTS][1600]; static ssize_t pending_n[PORTS];
    static cfg_t view;
    const char *line_spec[PORTS] = { NULL, NULL };
    char err[CFG_ERR_MAX];
    line_t line[PORTS];
    struct pollfd pfd[PORTS];
    uint8_t rx[LINE_BLOCK], tx[LINE_BLOCK];
    int16_t lin[LINE_BLOCK]; int is_lin = 0, blk_lin[PORTS] = { 0, 0 }, cap_lin = 0, max_tx_code = 0;
    const char *rx_formats = "";        /* -R */
    uint32_t seed = 0, now_ms = 0, listen_addr = 0, calls_seen[PORTS] = { 0, 0 };
    int opt, print_net = 0, line_law[PORTS] = { 0, 0 }, r, offhook = 0, i, p, blocks = 0, echo_delay = -1, listen_warned = 0, originate = 0;
    struct sigaction sa;
    const char *cap_path = NULL; int cap_fd = -1, cap_port = 0; long cap_n = 0;
    /* the telephone lights: <prefix><port>/brightness, lit while the port is off hook */
    const char *led_prefix = "/sys/class/leds/ht802:phone"; int led_fd[PORTS] = { -1, -1 }, led_on[PORTS] = { -1, -1 };

    while ((opt = getopt(argc, argv, "c:l:d:i:t:vpow:W:L:A:N:R:P:D:G:E:O:V:M:S:XB:b:J:T:u:U:Y:")) != -1) {
        switch (opt) {
        case 'c': cfg_path = optarg; break;
        case 'l': if (n_ports >= PORTS) usage(); line_spec[n_ports++] = optarg; break;
        case 'd': echo_delay = atoi(optarg); if (echo_delay < 0 || echo_delay > 1900) usage(); break;
        case 'i': lan_if = optarg; break;
        case 't': {
            size_t n = strlen(optarg);
            if (n == 0 || n >= sizeof tun_name[0] - 1) usage();
            strcpy(tun_name[0], optarg); strcpy(tun_name[1], optarg);
            /* the second port's device: the next digit, or a 1 appended */
            if (optarg[n - 1] >= '0' && optarg[n - 1] < '9') tun_name[1][n - 1]++;
            else { tun_name[1][n] = '1'; tun_name[1][n + 1] = '\0'; }
            break;
        }
        case 'v': force_debug = 1; log_level = CFG_LOG_DEBUG; break;
        case 'p': print_net = 1; break;
        case 'o': originate = 1; break;   /* bench: the box calls (srv_set_originate) */
        case 'L': led_prefix = optarg; break;
        case 'N': fw_tool = optarg; break;      /* the flash tool behind the Firmware page */
        case 'O': netsvc_set_vpnprog(optarg); break;  /* the OpenVPN program; "" = none */
        case 'M': satlink_set_match(optarg); break;   /* run instead of wget for a match query: CMD action game ip port */
        case 'X': satlink_set_any(1); break;          /* accept any matchmaking opponent address (testing only) */
        case 'S': {                              /* the STUN server as A.B.C.D[:port] (the test gives a stand-in) */
            unsigned q0, q1, q2, q3, pp = SATURN_STUN_PORT;
            if (sscanf(optarg, "%u.%u.%u.%u:%u", &q0, &q1, &q2, &q3, &pp) >= 4 && q0 < 256 && q1 < 256 && q2 < 256 && q3 < 256) {
                satlink_set_stun(q0 << 24 | q1 << 16 | q2 << 8 | q3, (uint16_t)pp);
            }
            break; }
        case 'B': bbslink_set_builtin(optarg); break; /* the bbs list in the image */
        case 'b': bbslink_set_fetch(optarg); break;   /* the command that prints the bbs list; "" = never fetch */
        case 'J': bbslink_set_live(optarg); break;    /* where a fetched bbs list is kept */
        case 'T': bbslink_set_prog(optarg); break;    /* run instead of nc to reach a board: PROG HOST PORT */
        case 'u': update_set_cmd(optarg); break;      /* the command that prints the latest release version; "" = never check */
        case 'U': fw_update_cmd = optarg; break;      /* run as CMD VERSION to install an update (instead of fwupdate.sh) */
        case 'Y': update_set_state(optarg); break;    /* where the available-update result is kept */
        case 'V': netsvc_set_vpnpath(optarg); break;  /* where the VPN profile is kept */
        case 'E': netsvc_set_lease(optarg); break;    /* prints the console's address on the network (instead of udhcpc) */
        case 'G': netsvc_set_dcnow(optarg); break;    /* run instead of wget for the Dreamcast Now report: PROG URL BODY */
        case 'D': netsvc_set_dclist(optarg); break;   /* the command that fetches the console address list; "" = none */
        case 'A': netsvc_set_arch(optarg); break;     /* the archive gateway program; "" = do not start one */
        case 'R': rx_formats = optarg; if (strlen(optarg) > PORTS || strspn(optarg, "lc") != strlen(optarg)) usage(); break;
        case 'P': max_tx_code = atoi(optarg); if (max_tx_code < 1 || max_tx_code > 31) usage(); break;
        case 'w': cap_path = optarg; break;
        case 'W': cap_path = optarg; cap_port = 1; break;    /* the same for port 2 */   /* bring-up: record port 1's line while off hook */
        default: usage();
        }
    }
    r = cfg_load(&live, cfg_path, err, sizeof err);
    if (r == CFG_ERR) { fprintf(stderr, "v90d: %s\n", err); return 1; }
    if (print_net) {
        char a[16], b[16], g[16], d1[16], d2[16];
        printf("LAN_MODE=%s\nLAN_ADDRESS=%s\nLAN_NETMASK=%s\n", live.lan_dhcp ? "dhcp" : "static",
               ip_str(live.lan_addr, a), ip_str(live.lan_netmask, b));
        /* empty = none */
        printf("LAN_GATEWAY=%s\nLAN_DNS1=%s\nLAN_DNS2=%s\n", live.lan_gateway ? ip_str(live.lan_gateway, g) : "",
               live.dns[0] ? ip_str(live.dns[0], d1) : "", live.dns[1] ? ip_str(live.dns[1], d2) : "");
        return 0;
    }
    if (!n_ports) usage();
    if (!force_debug) log_level = live.log_level;
    if (r == CFG_DEFAULTS) logf_(CFG_LOG_WARN, "%s not found: running on the defaults", cfg_path);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term; sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = SIG_IGN; sigaction(SIGPIPE, &sa, NULL);

    i = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (i >= 0) { if (read(i, &seed, sizeof seed) != (ssize_t)sizeof seed) seed = 0; close(i); }
    if (!seed) seed = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16);

    for (p = 0; p < n_ports; p++) {
        if (line_open(&line[p], line_spec[p]) < 0) { logf_(CFG_LOG_ERROR, "line %s: %s", line_spec[p], strerror(errno)); return 1; }
        cfg_for_port(&live, p, &view);
        line_law[p] = view.law == CFG_LAW_ALAW;
        if (line_set_law(&line[p], line_law[p]) < 0) logf_(CFG_LOG_WARN, "line %s: cannot set the law: %s", line_spec[p], strerror(errno));
        srv_init(&S[p], &view, seed + 0x9E3779B9u * (uint32_t)p, ip_to_kernel, &S[p]);
        srv_set_raw(&S[p], raw_from_modem);
        srv_set_echo_delay(&S[p], echo_delay);
        srv_set_max_tx_code(&S[p], max_tx_code);
        srv_set_originate(&S[p], originate);
        srv_set_heavy_slot(&S[p], &heavy_inflight);   /* one heavy call (x2 or K56flex) at a time across the ports */
        if ((size_t)p < strlen(rx_formats)) {
            if (line_set_linear(&line[p], rx_formats[p] == 'l') < 0)
                logf_(CFG_LOG_WARN, "line %s: cannot set the receive format: %s", line_spec[p], strerror(errno));
        } else if (line[p].dev && line_set_linear(&line[p], 1) < 0) {
            /* a driver from before the linear format: companded it stays */
            logf_(CFG_LOG_INFO, "line %s: no linear receive (%s), staying companded", line_spec[p], strerror(errno));
        }
        pfd[p].fd = line[p].fd; pfd[p].events = POLLIN;
        logf_(CFG_LOG_INFO, "port %d ready on line %s; number \"%s\"", p + 1, line_spec[p], view.line_number[0] ? view.line_number : "any");
    }
    netsvc_apply();
    httpd_init(&H, &live, &S[0].status);
    if (n_ports > 1) httpd_status2(&H, &S[1].status);
    httpd_on_save(&H, on_save, NULL);
    httpd_on_vpn(&H, netsvc_on_vpn, NULL);
    httpd_on_bbs(&H, bbslink_rows, NULL);
    httpd_on_diag(&H, diag_fill, NULL);
    { char r[48]; settings_set_vpn(netsvc_vpn_remote(r, sizeof r) ? r : NULL); }
    {
        static const httpd_fw_t fw = { V90D_VERSION " (built " __DATE__ ")", fw_text, fw_take, fw_install, NULL };
        httpd_on_firmware(&H, &fw);
    }
    update_config(live.update_check, V90D_VERSION);

    /* The line gives us 10 ms blocks and wants each answered in time; a late
     * one costs the caller's modem its training. So: ahead of everything
     * else on the box, and never waiting for a page. */
    {
        struct sched_param sp;
        memset(&sp, 0, sizeof sp); sp.sched_priority = 50;
        if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0) logf_(CFG_LOG_WARN, "no real-time priority: %s", strerror(errno));
        if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) logf_(CFG_LOG_WARN, "cannot lock the memory: %s", strerror(errno));
    }

    for (p = 0; p < n_ports; p++) {
        char path[300];
        snprintf(path, sizeof path, "%s%d/brightness", led_prefix, p + 1);
        led_fd[p] = open(path, O_WRONLY);       /* no such light: nothing is shown */
    }

    while (!stop) {
        /* the next block of either line; the first line's blocks count the time */
        r = poll(pfd, (nfds_t)n_ports, 1000);
        if (r < 0) { if (errno == EINTR) continue; logf_(CFG_LOG_ERROR, "poll: %s", strerror(errno)); break; }
        if (r == 0) continue;
        for (p = 0; p < n_ports && !stop; p++) {
            if (!(pfd[p].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            r = line_read2(&line[p], rx, lin, &is_lin, &offhook);
            if (r == 0) { logf_(CFG_LOG_INFO, "line closed"); stop = 1; break; }
            if (r < 0) { logf_(CFG_LOG_ERROR, "line: %s", strerror(errno)); stop = 1; break; }
            if (led_fd[p] >= 0 && (offhook != 0) != led_on[p]) {
                led_on[p] = offhook != 0;
                if (pwrite(led_fd[p], led_on[p] ? "1\n" : "0\n", 2, 0) < 0) { close(led_fd[p]); led_fd[p] = -1; }
            }
            if (is_lin != blk_lin[p]) {
                blk_lin[p] = is_lin;
                srv_set_rx_linear(&S[p], is_lin);      /* from the next call on */
                logf_(CFG_LOG_INFO, "port %d: the line now gives %s samples", p + 1, is_lin ? "16-bit linear" : "companded (G.711)");
            }
            if (is_lin) for (i = 0; i < LINE_BLOCK; i++) tx[i] = srv_tick_lin(&S[p], offhook, lin[i]);
            else for (i = 0; i < LINE_BLOCK; i++) tx[i] = srv_tick(&S[p], offhook, rx[i]);
            if (p == cap_port && cap_path) {
                /* 80 codewords heard, then the 80 sent in answer, per block; 8 MB at most */
                if (offhook && cap_fd < 0 && cap_n == 0) {
                    cap_fd = open(cap_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    cap_lin = is_lin;                   /* a recording is of one kind */
                    if (cap_fd >= 0 && cap_lin && write(cap_fd, "V90DLIN1", 8) < 0) cap_n = 50000;
                }
                if (cap_fd >= 0 && offhook && cap_n < 50000 && is_lin != cap_lin) cap_n = 50000;
                if (cap_fd >= 0 && offhook && cap_n < 50000) {
                    uint8_t heard[2 * LINE_BLOCK]; size_t hn = LINE_BLOCK;
                    if (!is_lin) memcpy(heard, rx, LINE_BLOCK);
                    else for (hn = 0; hn < 2 * LINE_BLOCK; hn += 2) { heard[hn] = (uint8_t)((uint16_t)lin[hn / 2] & 255); heard[hn + 1] = (uint8_t)((uint16_t)lin[hn / 2] >> 8); }
                    if (write(cap_fd, heard, hn) < 0 || write(cap_fd, tx, LINE_BLOCK) < 0) cap_n = 50000;
                    cap_n++;
                }
                if (!offhook && cap_fd >= 0) { close(cap_fd); cap_fd = -1; }
                if (!offhook && cap_n && access(cap_path, F_OK) != 0) cap_n = 0;   /* file taken away: record the next call */
            }
            if (line_write(&line[p], tx) < 0) { logf_(CFG_LOG_ERROR, "line: %s", strerror(errno)); stop = 1; break; }
            /* packets for the caller; one that does not fit yet is kept */
            if (tun_fd[p] >= 0) {
                for (i = 0; i < 16; i++) {
                    if (pending_n[p] <= 0) pending_n[p] = read(tun_fd[p], pending[p], sizeof pending[p]);
                    if (pending_n[p] <= 0) break;
                    r = srv_send_ip(&S[p], pending[p], (size_t)pending_n[p]);
                    if (r == PPP_ERR_FULL) break;
                    pending_n[p] = 0;               /* sent, or nobody to send it to */
                }
            }
            if (S[p].status.calls_total != calls_seen[p]) { calls_seen[p] = S[p].status.calls_total; log_last_call(p); }
            if (S[p].tel.state == TEL_ONHOOK) {
                cfg_for_port(&live, p, &view);
                if (line_law[p] != (view.law == CFG_LAW_ALAW)) { line_law[p] = view.law == CFG_LAW_ALAW; (void)line_set_law(&line[p], line_law[p]); }
            }
            if (p != 0) continue;

            /* once per block of the first line: everything that is not a line */
            now_ms += 10;
            if (all_onhook()) {
                if (have_unsaved) { have_unsaved = 0; (void)store(&unsaved); }
                if (net_dirty) netsvc_apply();
            }
            satlink_poll(now_ms);
            bbslink_poll(now_ms);
            update_poll(now_ms);
            netsvc_poll(now_ms);
            if (fw_pid > 0 && now_ms % 1000 == 0 && waitpid(fw_pid, NULL, WNOHANG) == fw_pid) fw_pid = 0;
            /* the Restart button, once its answer has gone out */
            if (H.restart_asked && httpd_active(&H) == 0) {
                int fd;
                H.restart_asked = 0;
                logf_(CFG_LOG_INFO, "restart asked on the settings page");
                /* The daemon does not restart the machine it runs on: it leaves a
                 * note, and the image's boot script (fw/rcS) keeps what must be
                 * kept and restarts. */
                fd = open(RESTART_NOTE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (fd >= 0) close(fd);
                else logf_(CFG_LOG_WARN, "cannot write %s: %s", RESTART_NOTE, strerror(errno));
            }
            /* once a second: wall clock, and the LAN address may have changed (DHCP) */
            if (++blocks >= 100) {
                time_t t = time(NULL);
                blocks = 0;
                for (i = 0; i < n_ports; i++)
                    if (t > 1600000000 && S[i].tel.state == TEL_ONHOOK) srv_set_clock(&S[i], (uint32_t)t);
                if (live.status_listen == CFG_LISTEN_LAN) {
                    uint32_t a = if_address(lan_if);
                    if (a != listen_addr || (a && H.listen_fd < 0)) {
                        char b[16];
                        httpd_close(&H); listen_addr = 0;
                        /* on every address of the LAN interface where the system lets us
                         * tie the socket to it (so also on the image's rescue address),
                         * else on its address */
                        if (a && (httpd_listen(&H, 0, (uint16_t)live.status_port, lan_if) == 0 ||
                                  httpd_listen(&H, a, (uint16_t)live.status_port, lan_if) == 0)) {
                            listen_addr = a; listen_warned = 0;
                            logf_(CFG_LOG_INFO, "status and settings on http://%s:%d/", ip_str(a, b), live.status_port);
                        } else if (a && !listen_warned) {
                            listen_warned = 1;
                            logf_(CFG_LOG_WARN, "cannot listen on %s:%d: %s", ip_str(a, b), live.status_port, strerror(errno));
                        }
                    }
                } else if (H.listen_fd >= 0) {
                    httpd_close(&H); listen_addr = 0;
                }
            }
            httpd_poll(&H, now_ms);
        }
    }

    httpd_close(&H);
    netsvc_stop();
    bbslink_stop();
    update_stop();
    for (p = 0; p < n_ports; p++) line_close(&line[p]);
    logf_(CFG_LOG_INFO, "stopped");
    return 0;
}
