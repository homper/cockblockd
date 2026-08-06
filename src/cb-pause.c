// SPDX-License-Identifier: GPL-2.0
//
// cb-pause - interactive single-question client for cockblock's pause.
//
// Run in a terminal: /opt/cockblock/cb-pause
//   - refuses unless stdin/stdout are a real tty (blocks pipes/redirects)
//   - connects to the daemon's abstract unix socket, gets ONE math question
//     with a live countdown, reads your typed answer, sends it back, prints
//     correct/wrong/granted, then exits. Run it again for the next question.
//
// The daemon verifies this binary's identity (uid + /proc/pid/exe + sha256)
// before trusting the answer, so a script/copied binary can't fake it.
//
// Env: none.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#define SOCK_NAME "cockblock-pause"   // abstract unix socket
#define QUESTIONS 5
#define RECV_TIMEOUT 40               // daemon cycles ~28s; allow margin

static int dial(void) {
	for (int i = 0; i < 60; i++) {
		int s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) return -1;
		struct sockaddr_un a;
		memset(&a, 0, sizeof a);
		a.sun_family = AF_UNIX;
		a.sun_path[0] = '\0';
		size_t nl = strlen(SOCK_NAME);
		memcpy(a.sun_path + 1, SOCK_NAME, nl);
		socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 1 + nl;
		if (connect(s, (struct sockaddr *)&a, alen) == 0) return s;
		close(s);
		sleep(1);
	}
	return -1;
}

static int send_line(int s, const char *line) {
	size_t l = strlen(line), off = 0;
	while (off < l) { ssize_t w = write(s, line + off, l - off); if (w <= 0) return -1; off += w; }
	if (line[l - 1] != '\n' && write(s, "\n", 1) != 1) return -1;
	return 0;
}

static int recv_line(int s, char *buf, size_t n, int timeout_s) {
	size_t got = 0; time_t start = time(NULL);
	while (got < n - 1) {
		fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
		long left = timeout_s - (time(NULL) - start); if (left < 1) left = 1;
		struct timeval tv = { left, 0 };
		int r = select(s + 1, &rf, NULL, NULL, &tv);
		if (r <= 0) return -1;
		ssize_t rd = read(s, buf + got, n - 1 - got);
		if (rd <= 0) return -1;
		got += rd; buf[got] = 0;
		if (memchr(buf, '\n', got)) break;
	}
	buf[got] = 0;
	char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
	return 0;
}

// Read an answer line from the terminal with a live countdown to deadline.
// Uses raw mode (no echo / no canonical) and redraws ONE line each second and
// on every keystroke with "\r\033[K" (clear-to-end), so the countdown and your
// typed text share the line cleanly, the cursor is always at the right place,
// backspace works, and arrow-key escape sequences are drained (ignored).
static int read_answer(char *out, size_t n, time_t deadline) {
	struct termios oldt, newt;
	if (tcgetattr(STDIN_FILENO, &oldt) != 0) return -1;
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	newt.c_cc[VMIN] = 1; newt.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	size_t len = 0;
	size_t pos = 0;
	int rc = -1;
	while (1) {
		time_t now = time(NULL);
		long left = (long)(deadline - now);
		if (left <= 0) { printf("\r\033[KTime's up.\n"); break; }
		printf("\r\033[KTime left: %-4lds | answer> %.*s", left, (int)len, out);
		if (pos < len) printf("\033[%zdD", len - pos);   // move cursor left to pos
		fflush(stdout);
		fd_set rf; FD_ZERO(&rf); FD_SET(STDIN_FILENO, &rf);
		struct timeval tv; tv.tv_sec = (left > 1) ? 1 : left; tv.tv_usec = 0;
		int r = select(STDIN_FILENO + 1, &rf, NULL, NULL, &tv);
		if (r > 0) {
			char ch; ssize_t rd = read(STDIN_FILENO, &ch, 1);
			if (rd <= 0) break;
			if (ch == '\n' || ch == '\r') { printf("\n"); rc = 0; break; }
			else if (ch == 0x7f || ch == 0x08) { if (pos > 0) { memmove(out + pos - 1, out + pos, len - pos); len--; pos--; } }
			else if (ch == 0x01) pos = 0;            // Ctrl-A: home
			else if (ch == 0x05) pos = len;          // Ctrl-E: end
			else if (ch == 0x1b) {                   // ESC: parse a CSI/arrow seq
				char b1 = 0, b2 = 0, b3 = 0;
				struct timeval z = { 0, 50000 };
				fd_set f2; FD_ZERO(&f2); FD_SET(STDIN_FILENO, &f2);
				if (select(STDIN_FILENO + 1, &f2, NULL, NULL, &z) > 0) { (void)!read(STDIN_FILENO, &b1, 1);
					if (b1 == '[') { if (select(STDIN_FILENO + 1, &f2, NULL, NULL, &z) > 0) { (void)!read(STDIN_FILENO, &b2, 1);
						if (b2 == '3') { if (select(STDIN_FILENO + 1, &f2, NULL, NULL, &z) > 0) (void)!read(STDIN_FILENO, &b3, 1); } } } }
				if (b1 == '[') {
					if (b2 == 'D') { if (pos > 0) pos--; }            // left
					else if (b2 == 'C') { if (pos < len) pos++; }     // right
					else if (b2 == 'H') pos = 0;                     // home
					else if (b2 == 'F') pos = len;                   // end
					else if (b2 == '3' && b3 == '~') { if (pos < len) { memmove(out + pos, out + pos + 1, len - pos - 1); len--; } }  // delete
				} else if (b1 == 'O') {
					if (b2 == 'D') { if (pos > 0) pos--; }
					else if (b2 == 'C') { if (pos < len) pos++; }
					else if (b2 == 'H') pos = 0;
					else if (b2 == 'F') pos = len;
				}
			}
			else if (isprint((unsigned char)ch) && len < n - 1) { memmove(out + pos + 1, out + pos, len - pos); out[pos] = ch; len++; pos++; }
		}
	}
	out[len] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return rc;
}

int main(void) {
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		fprintf(stderr, "cb-pause: run this from a real terminal (not a pipe/redirect).\n");
		return 1;
	}

	// --- HELLO connection: fetch the current state (one short connection so
	// the daemon's ~28s restart cycle can't drop it mid-answer). ---
	int s = dial();
	if (s < 0) { fprintf(stderr, "cb-pause: cannot reach the daemon (is cockblock running?).\n"); return 1; }
	if (send_line(s, "HELLO") < 0) { fprintf(stderr, "cb-pause: send failed.\n"); return 1; }
	char resp[1024];
	if (recv_line(s, resp, sizeof resp, RECV_TIMEOUT) < 0) {
		fprintf(stderr, "cb-pause: no response from the daemon.\n"); return 1;
	}
	close(s);

	if (!strncmp(resp, "QUESTION", 8)) {
		int n; char nonce[128]; long long deadline; char qtext[512];
		if (sscanf(resp, "QUESTION %d %127s %lld %511[^\n]", &n, nonce, &deadline, qtext) < 4) {
			fprintf(stderr, "cb-pause: bad question from daemon: %s\n", resp); return 1;
		}
		printf("Question %d/%d: %s\n", n, QUESTIONS, qtext);
		char ans[256];
		if (read_answer(ans, sizeof ans, (time_t)deadline) < 0) return 1;  // timed out

		// --- ANSWER connection: a fresh short connection to submit + get the
		// result. (Separate from HELLO so the long typing pause doesn't sit on
		// a connection the daemon would close on its restart cycle.) ---
		int s2 = dial();
		if (s2 < 0) { fprintf(stderr, "cb-pause: cannot reach the daemon to submit.\n"); return 1; }
		char msg[1200];
		snprintf(msg, sizeof msg, "ANSWER %s %s", nonce, ans);
		if (send_line(s2, msg) < 0) { fprintf(stderr, "cb-pause: send failed.\n"); close(s2); return 1; }
		char res[1024];
		if (recv_line(s2, res, sizeof res, RECV_TIMEOUT) < 0) {
			fprintf(stderr, "cb-pause: no response.\n"); close(s2); return 1;
		}
		close(s2);
		if (!strncmp(res, "CORRECT", 7)) {
			printf("Correct! Wait 60s, then open cb-pause again within the next 60s.\n");
			return 0;
		} else if (!strncmp(res, "GRANTED", 7)) {
			printf("%s\n", res + 8);
			return 0;
		} else if (!strncmp(res, "WRONG", 5)) {
			long long cd = 0; sscanf(res, "WRONG %lld", &cd);
			if (cd > 0) printf("Wrong answer. Locked out for %llds.\n", cd);
			else printf("Wrong answer. Start over.\n");
			return 1;
		} else if (!strncmp(res, "TIMEOUT", 7)) {
			long long cd = 0; sscanf(res, "TIMEOUT %lld", &cd);
			if (cd > 0) printf("Time's up. Locked out for %llds.\n", cd);
			else printf("Time's up. Start over.\n");
			return 1;
		} else if (!strncmp(res, "STALE", 5)) {
			printf("That question is no longer current. Start over.\n");
			return 1;
		}
		printf("Daemon: %s\n", res);
		return 1;
	} else if (!strncmp(resp, "WAIT", 4)) {
		long long secs = 0;
		sscanf(resp, "WAIT %lld", &secs);
		printf("Next question is in %llds. Run cb-pause again then.\n", secs);
		return 0;
	} else if (!strncmp(resp, "COOLDOWN", 8)) {
		long long secs = 0;
		sscanf(resp, "COOLDOWN %lld", &secs);
		printf("Locked out due to a failed attempt. Try again in %llds.\n", secs);
		return 1;
	} else if (!strncmp(resp, "GRANTED", 7)) {
		printf("Already unblocked: %s\n", resp + 8);
		return 0;
	} else if (!strncmp(resp, "LIMIT", 5)) {
		printf("Daily pause limit reached. Try again tomorrow.\n");
		return 1;
	}
	printf("Daemon: %s\n", resp);
	return 1;
}
