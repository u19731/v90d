/* v90d/cfg - the Firmware page. See firmware.h. */
#include <string.h>
#include "firmware.h"
#include "sbuf.h"
#include "page.h"

int firmware_value(const char *where, const char *name, char *out, size_t cap)
{
    size_t k = strlen(name), i;
    const char *p = where;

    if (cap) out[0] = '\0';
    while (p && *p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > k && p[k] == '=' && memcmp(p, name, k) == 0) {
            for (i = 0; i + 1 < cap && k + 1 + i < len; i++) out[i] = p[k + 1 + i];
            if (cap) out[i] = '\0';
            return 1;
        }
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static void row(sbuf_t *b, const char *label, const char *value)
{
    sb_puts(b, "<tr><th>"); sb_puts(b, label); sb_puts(b, "</th><td>");
    sb_html(b, value, FIRMWARE_TEXT_MAX, 0);
    sb_puts(b, "</td></tr>\n");
}

/* 1 if the box was started in a way that leaves something to write to */
static int scheme_of(const char *where, char *set, size_t cap)
{
    char s[16];
    firmware_value(where, "set", set, cap);
    if (!firmware_value(where, "scheme", s, sizeof s)) return 0;
    if (strcmp(s, "loader") == 0) return 2;
    if (strcmp(s, "old") == 0) return 1;
    return 0;
}

int firmware_render_html(const char *version, const char *where, const char *state, int can_write, char *buf, size_t cap)
{
    sbuf_t b;
    char v[160], set[8];
    int scheme;

    if (!where) where = "";
    if (!state) state = "";
    scheme = scheme_of(where, set, sizeof set);
    sb_init(&b, buf, cap);
    page_top(&b, "firmware", "", PAGE_TAB_FIRMWARE, NULL);

    sb_puts(&b, "<section><h2>This firmware</h2>\n<table>\n");
    row(&b, "Version", version ? version : V90D_VERSION);
    sb_puts(&b, "<tr><th>Started</th><td>");
    if (scheme == 2) {
        sb_puts(&b, "by the v90d loader, from set "); sb_html(&b, set, sizeof set, 0);
        sb_puts(&b, " of the flash");
    } else if (scheme == 1) {
        sb_puts(&b, "the bench way: by a script in the boot loader's settings, from a fixed place in the flash");
    } else {
        sb_puts(&b, "from memory, or in a way this firmware does not know. Nothing can be written to the flash from here.");
    }
    sb_puts(&b, "</td></tr>\n");
    if (firmware_value(where, "image_name", v, sizeof v)) {
        char n[16];
        sb_puts(&b, "<tr><th>In the flash</th><td>"); sb_html(&b, v, sizeof v, 0);
        if (firmware_value(where, "image_octets", n, sizeof n)) { sb_puts(&b, ", "); sb_html(&b, n, sizeof n, 0); sb_puts(&b, " octets"); }
        sb_puts(&b, "<small>What the next start will run.</small></td></tr>\n");
    } else if (scheme) {
        row(&b, "In the flash", "no system image that checks: the next start is the stock firmware");
    }
    if (firmware_value(where, "installed", v, sizeof v) && strcmp(v, "whole") != 0)
        row(&b, "Installation", "not complete: the stock firmware's upgrade did not finish writing the file. Give it the file again.");
    if (firmware_value(where, "unconfirmed", v, sizeof v) || firmware_value(where, "old_tries", v, sizeof v)) {
        int old = !firmware_value(where, "unconfirmed", v, sizeof v);
        if (old) firmware_value(where, "old_tries", v, sizeof v);
        sb_puts(&b, "<tr><th>"); sb_puts(&b, old ? "Starts left" : "Starts not confirmed"); sb_puts(&b, "</th><td>");
        sb_html(&b, v, sizeof v, 0);
        sb_puts(&b, "<small>A start counts as good once the box has run for a minute. After three in a row that"
                    " did not get that far, the box starts the stock firmware again.</small></td></tr>\n");
    }
    if (firmware_value(where, "stock", v, sizeof v)) {
        sb_puts(&b, "<tr><th>Stock firmware</th><td>in set "); sb_html(&b, v, sizeof v, 0); sb_puts(&b, "</td></tr>\n");
    }
    if (firmware_value(where, "board", v, sizeof v)) row(&b, "Board", v);
    sb_puts(&b, "</table></section>\n");

    if (firmware_value(where, "update_avail", v, sizeof v) && v[0]) {
        sb_puts(&b, "<section><h2>Update available</h2>\n<p>Version ");
        sb_html(&b, v, sizeof v, 0);
        sb_puts(&b, " has been released. <a href=\"https://github.com/georgica/v90d/releases/tag/v");
        sb_html(&b, v, sizeof v, 0);
        sb_puts(&b, "\">Release notes</a>.</p>\n");
        if (can_write && scheme) {
            sb_puts(&b, "<p>Install it: the box downloads the release from GitHub, checks it in full (a damaged"
                        " file or one for another box is refused), writes the spare flash copy and restarts into"
                        " it. The stock firmware and your settings are kept. Not while a call is in progress.</p>\n"
                        "<form method=\"post\" action=\"/firmware/update\">\n"
                        "<p><input type=\"submit\" value=\"Download and install\"></p>\n</form>\n");
        } else {
            sb_puts(&b, "<p>This system has no place in the flash to write to, so it cannot be installed from here.</p>\n");
        }
        sb_puts(&b, "</section>\n");
    }

    if (state[0]) {
        sb_puts(&b, "<section><h2>Last upload</h2>\n<p>");
        sb_html(&b, state, FIRMWARE_TEXT_MAX, 0);
        sb_puts(&b, "</p></section>\n");
    }

    sb_puts(&b, "<section><h2>Upload new firmware</h2>\n");
    if (can_write && scheme) {
        sb_puts(&b, "<form method=\"post\" action=\"/firmware/upload\" enctype=\"multipart/form-data\">\n"
                    "<p>The v90d firmware file (the same file that goes on the stock firmware's upgrade page), or a"
                    " bare system image &mdash; a v90d image of a few megabytes, <strong>not</strong> a Grandstream"
                    " firmware file. It is checked in full before anything is written: a file that is damaged, built"
                    " for another box, or not a v90d image is refused and nothing changes. Not while a call is in"
                    " progress.</p>\n"
                    "<p>To go back to the stock Grandstream firmware, do not upload it here &mdash; use"
                    " &ldquo;Back to the stock firmware&rdquo; below. (A file much larger than a v90d image, such as"
                    " a full Grandstream image, is turned away before it finishes sending, which a browser may show"
                    " as a reset rather than a message.)</p>\n"
                    "<p>Writing takes a few minutes, then the box restarts by itself. Leave the power on: if it"
                    " goes while the flash is being written, the box starts the stock firmware and the file has"
                    " to be given to that again. The settings are kept.</p>\n"
                    "<p><input type=\"file\" name=\"image\" required> <input type=\"submit\" value=\"Upload and write\"></p>\n"
                    "</form>\n");
    } else {
        sb_puts(&b, "<p>Not from here: this system has no place in the flash to write to.</p>\n");
    }
    sb_puts(&b, "</section>\n");

    sb_puts(&b, "<section><h2>Back to the stock firmware</h2>\n");
    if (can_write && scheme) {
        sb_puts(&b, "<p>The stock firmware is still in the box, untouched, and one change makes the box start it"
                    " again. The next page says what that means and asks before it does it.</p>\n"
                    "<p><a href=\"/firmware/stock\">Back to the stock firmware&hellip;</a></p>\n");
    } else {
        sb_puts(&b, "<p>Not from here: restart the box, it starts what is in its flash.</p>\n");
    }
    sb_puts(&b, "</section>\n" PAGE_END);
    return sb_end(&b);
}

int firmware_render_stock(const char *where, char *buf, size_t cap)
{
    sbuf_t b;
    char v[160], set[8];
    int scheme;

    if (!where) where = "";
    scheme = scheme_of(where, set, sizeof set);
    sb_init(&b, buf, cap);
    page_top(&b, "firmware", "", PAGE_TAB_FIRMWARE, NULL);
    sb_puts(&b, "<form method=\"post\" action=\"/firmware/stock\">\n"
                "<section><h2>Back to the stock firmware</h2>\n"
                "<p>What happens:</p>\n<table>\n");
    if (scheme == 1)
        row(&b, "In the flash", "The start count in the boot loader's settings is taken out. The boot loader then"
                                " starts the stock firmware, as it did before v90d was put on the box. Nothing else is"
                                " written; the v90d image stays where it is, unused.");
    else
        row(&b, "In the flash", "Four octets are written: the mark by which the boot loader knows the v90d set is"
                                " taken away. The boot loader then starts the other set, the stock firmware, which"
                                " was never written to. This is the same thing the v90d loader does by itself after"
                                " three starts that failed.");
    row(&b, "Then", "The box restarts, at once. Calls in progress are cut off.");
    row(&b, "After that", "The box runs the stock firmware with the settings, the address and the password it had"
                          " when it last ran it. This page is gone.");
    row(&b, "Coming back", "On the stock firmware's upgrade page, upload the v90d firmware file again. The v90d"
                           " settings are not kept across that: the stock upgrade erases the place they are in.");
    if (firmware_value(where, "stock", v, sizeof v)) {
        sb_puts(&b, "<tr><th>Stock firmware now</th><td>in set "); sb_html(&b, v, sizeof v, 0);
        sb_puts(&b, "<small>It is checked once more before anything is written. If it does not check, nothing"
                    " is changed.</small></td></tr>\n");
    }
    sb_puts(&b, "</table>\n"
                "<p><label><input type=\"checkbox\" name=\"confirm\" value=\"stock\" required>"
                " Yes, put this box back on the stock firmware</label></p>\n"
                "<p><input type=\"submit\" value=\"Back to stock and restart\"> &nbsp; <a href=\"/firmware\">No, go back</a></p>\n"
                "</section>\n</form>\n" PAGE_END);
    return sb_end(&b);
}
