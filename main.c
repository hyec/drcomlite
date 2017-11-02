#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h> 
#include <getopt.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include "md5.h"

/* CHANGE it in before compile. */

const char*	defHost = "DRCOM";
const char*	defOs = "Linux";
const char*	defDNS = "10.10.10.10";
const char*	defDHCP = "0.0.0.0";

/* Configs above are for what and compile by whom */

#define FOR_WHAT "JLU"
#define BY_WHOM ""

/* Read this carefully and start you compile. */

const char *README =

"\n  DrcomLite for Xiaomi Router.  \n"
"--------------------------------\n"
" 1. This Project is only for learning. \n"
" 2. DON'T use it without permision. \n"
" USEAGE: drcom [commands] \n"
"  -u user -p password [required] \n"
"  -i [IPaddress] -m [MACaddress] \n"
"  -h [HostName]  -o [OsName] \n"
"  -I to install auto start script. \n"
"  -h Show this help. \n"
"  -d Run in daemon. \n"
"--------------------------------\n"
" A Copy For " FOR_WHAT " By " BY_WHOM ".\n";

const char *macFormat = "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx";

in_addr_t srvip = (in_addr_t)(-1);
uint16_t port = 61440;
uint8_t mac[6] = { 0 };

uint8_t authVer[2] = { 0x68, 0x00 };
uint8_t controlCheck = 0x20;
uint8_t adapterNum = 0x04;
uint8_t keepaliveVer[2] = { 0xdc, 0x02 };
uint8_t ipDog = 0x01;

char serv[32];
char user[36];
char pass[16];
char host[32];
char cmac[20];

struct conf {
	const char *option;
	char *value;
} confs[] = {
	{ "server", serv },
	{ "user", user },
	{ "pass", pass },
	{ "host", host },
	{ "mac", cmac },
	{ NULL, NULL }
};



uint8_t salt[4];
uint8_t md5a[16];
uint8_t tail[16];
uint8_t tail2[4];
uint8_t flux[4];
uint16_t randtimes;
in_addr_t ip;
int alivesum = 0;

#define	h_addr	h_addr_list[0]

void readArgs(int argc, char *argv[]);
int readConf(const char file[]);
ssize_t recvCustom();

int	getmac(in_addr_t, uint8_t*);
int	readmac(const char*, uint8_t*);

int challenge(in_addr_t*, int);
int login();
int alive();

void ror(const uint8_t*, const char*, size_t, uint8_t*);
void checksum(const uint8_t*, size_t, uint8_t*);

int sock;

int debug = 0;
int trytimes = 3;
char *fileConf = "/etc/drcom.conf";

#define BUFFER_SIZE 1024
uint8_t buffer[BUFFER_SIZE];

int main(int argc, char *argv[])
{
	int ret = 0;

	readArgs(argc, argv);
	readConf(fileConf);

	if (debug != 1) {

		if (freopen("/var/log/drcom.log", "a", stderr) == NULL) {
			printf("Cannot reopen log file!\n");
		}
	}

	if (serv == NULL || user == NULL || pass == NULL)
	{
		fprintf(stderr, "invalid userinfo. use -h for help.\n");
		return EXIT_FAILURE;
	}

	if (debug != 1) {

		switch (ret = fork()) {
		case -1:
			close(sock);
			fprintf(stderr, "Failed to fork in daemon!\n");
			fprintf(stdout, "Failed to fork in daemon!\n");
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			fprintf(stdout, "Running in daemon(pid:%d)!\n", ret);
			exit(EXIT_SUCCESS);
		}

		umask(0);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		
		if (setsid() < 0 || chdir("/") < 0) {
			fprintf(stderr, "Failed to run in daemon!\n");
			exit(EXIT_FAILURE);
		}
	}

	struct addrinfo serv_addr;
	struct addrinfo* result;

	memset(&serv_addr, 0, sizeof(struct addrinfo));
	serv_addr.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	serv_addr.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	serv_addr.ai_flags = 0;
	serv_addr.ai_protocol = IPPROTO_UDP;          /* Any protocol */

	if((ret = getaddrinfo(serv, "61440", &serv_addr, &result)) != 0) {
		fprintf(stderr, "Invalid server(%s): %s\n", serv, gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("Create socket fail");
		return EXIT_FAILURE;
	}

	ret = 0;
	// while (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0)
	while (connect(sock, result->ai_addr, result->ai_addrlen) != 0)
	{
		perror("Connect to server fail");
		if (trytimes >= 0 && ret++ > trytimes)
			return EXIT_FAILURE;
		sleep(1);
	}

	if (cmac[0] == '\0' || readmac(cmac, mac) != 0)
	{
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		getsockname(sock, (struct sockaddr *)&client_addr, &client_len);

		in_addr_t ip_addr = client_addr.sin_addr.s_addr;

		if (	getmac(ip_addr, mac) != 0)
		{
			fprintf(stderr, "Unable to get the MAC address.\n"
				"You should set it in configure.\n");
			exit(EXIT_FAILURE);
		}
	}

	ret = 0;
	while (1)
	{
		if (trytimes >= 0 && ret++ > trytimes) {
			fprintf(stderr, "! try over times, login fail!\n");
			exit(EXIT_FAILURE);
		}

		if (challenge(&ip, ret) < 0) continue;
		
		if (login() < 0) continue;
			
		break;
	}
	

	while (1)
	{
		ret = 0;
		while (alive() != 0)
		{
			if (trytimes >= 0 && ret++ > trytimes)
			{
				fprintf(stderr, "alive(): fail;\n");
				exit(EXIT_FAILURE);
			}
			sleep(1);
		}
		sleep(20);
	}
	
	shutdown(sock, SHUT_RDWR);
    return 0;
}

int challenge(in_addr_t *resIp, int times)
{
	
	memset(buffer, 0, 20); 
	buffer[0] = 0x01;
	buffer[1] = 0x02 + (unsigned char)times;
	buffer[2] = (unsigned char)rand();
	buffer[3] = (unsigned char)rand();
	buffer[4] = 0x68;

	send(sock, buffer, 20, 0);

	ssize_t recv_len = recvCustom();
	if (recv_len <= 0) {
		fprintf(stderr, "Challenge timeout.\n");
		return -1;
	}

	if (buffer[0] != 0x02)
	{
		fprintf(stderr, "Challenge fail, unrecognized responese: %hhx.\n", buffer[0]);
		return -1;
	}

	memcpy(salt, &buffer[4], 4);

	if (resIp != NULL && recv_len >= 25)
	{
		/**resIp = 0;
		for (i = 20; i < 25; i++)
		{
			*resIp *= 0x100;
			*resIp += buffer[i];
		}*/
		memcpy(resIp, buffer + 20, 4);
	}

	return 0;
}

int login()
{
	int login_package_build();
	int len = login_package_build();

	send(sock, buffer, len, 0);

	ssize_t recv_len = recvCustom();
	if (recv_len <= 0) {
		fprintf(stderr, "Login timeout.\n");
		return -1;
	}

	if (buffer[0] != 0x04)
	{
		if (buffer[0] == 0x05) {
			fprintf(stderr, "Login fail, wrong password or username!\n");
		} else {
			fprintf(stderr, "Login fail, unrecognized responese: %hhx.\n", buffer[0]);
		}
		close(sock);
		exit(EXIT_FAILURE);
	}

	memcpy(tail, &buffer[0x17], 16);

	fprintf(stderr, "Login success!\n");
	return 0;
}

int alive()
{
	void keepalive_build(int, long);

	int i;
	randtimes = random() % 0xFFFF;

	for (i = 0; i < 3; i++)
	{
		keepalive_build(i, randtimes);
		send(sock, buffer, i == 0 ? 38 : 40, 0);

		if (recvCustom() < 0) {
			fprintf(stderr, "Alive(%d) timeout.\n", i);
			return -1;
		}
		if (buffer[0] != 0x07)
		{
			fprintf(stderr, "Alive fail, unrecognized responese: %hhx.\n", buffer[0]);
			return -1;
		}
		
		if(i > 0)
			memcpy(flux, &buffer[16], 4);
	}
	return 0;
}

ssize_t recvCustom()
{
	ssize_t ret;
	fd_set read_set;
recvReset:

	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);

	struct timeval timeout = { 3, 0 };
	switch (select(sock + 1, &read_set, NULL, NULL, &timeout)) {
	case 0:
		return -1;
	case -1:
		perror("select()");
	}

	ret = recv(sock, buffer, sizeof(buffer), 0);
	if (ret < 0) {
		perror("recv()");
		exit(EXIT_FAILURE);
	}

	if (buffer[0] == 0x4D) {
		if (buffer[1] == 0x15) {
			fprintf(stderr, "! Others logined.\n");
			exit(EXIT_FAILURE);
		}

		goto recvReset;
	}

	return ret;
}

int login_package_build()
{

	int i;
	uint8_t md5tmp[16];

	/* count the length of name and passwd */
	size_t user_len = strlen(user);
	size_t pass_len = strlen(pass);
	if (user_len > 36) user_len = 36;

	memset(buffer, 0, 333 + pass_len);

	/* md5b(0x01 passwd salt 0x00*4) */
	buffer[0] = 0x01;
	memcpy(&buffer[1], pass, pass_len);
	memcpy(&buffer[1 + pass_len], salt, 4);
	memset(&buffer[5 + pass_len], 0x00, 4);
	MD5(buffer, 9 + pass_len, md5tmp);

	/* md5a(code type salt passwd) */
	buffer[0] = 0x03; // package code
	buffer[1] = 0x01; // package type
	memcpy(&buffer[2], salt, 4);
	memcpy(&buffer[6], pass, pass_len);
	MD5(buffer, pass_len + 6, md5a);

	/* (4) package head 0x3 0x1 0x0 len+20 */
	buffer[2] = 0x00; 
	buffer[3] = (uint8_t)(user_len + 20);

	/* (16) md5a */
	memcpy(&buffer[4], md5a, 16);

	/* (36) username */
	//memset(&buffer[20], 0x00, 36);
	memcpy(&buffer[20], user, user_len);

	/* (2) ccs ada */
	buffer[56] = controlCheck;
	buffer[57] = adapterNum;

	/* (6) mac xor md5a */
	memcpy(&buffer[58], md5a, 6);
	for (i = 0; i < 6; i++)
		buffer[58 + i] ^= mac[i];

	/* (16) md5b */
	memcpy(&buffer[64], md5tmp, 16);

	/* (17) nic ip*4 */
	buffer[80] = 0x01;
	memcpy(&buffer[81], &ip, 4);
	memset(&buffer[85], 0x00, 4 * 3);

	/* (8) checksum */
	memcpy(&buffer[97], "\x14\x00\x07\x0b", 4);
	MD5(buffer, 101, md5tmp);
	memcpy(&buffer[97], md5tmp, 8);

	/* (5) ipdog 0x00*4 */
	buffer[105] = ipDog;

	/* (32) hostname */
	strcpy(&buffer[110], host);

	/* (12) dns dhcp dns */
	in_addr_t ip = inet_addr(defDNS);
	memcpy(&buffer[142], &ip, 4);
	ip = inet_addr(defDHCP);
	memcpy(&buffer[146], &ip, 4);

	/* (8) zero */

	/* (4) unknown */
	buffer[162] = 0x94;
	/* (4) os major */
	buffer[166] = 0x06;
	/* (4) os minor */
	buffer[170] = 0x02;
	/* (4) os build */
	buffer[174] = 0xf0;
	buffer[175] = 0x23;
	/* (4) os unknown */
	buffer[178] = 0x02;

	/* (8) DRCOM CHECK */
	memcpy(&buffer[182], "\x44\x72\x43\x4F\x4d\x00\xCF\x07", 8);
	
	/* (56) key2 */
	buffer[190] = 0x68;

	/* (40) key3 */
	memcpy(&buffer[246], "3dc79f5212e8170acfa9ec95f1d74916542be7b1", 40);

	/* (22) zero */
	//[286]

	/* (4) unknow 0x00*2 pass_len */
	buffer[310] = 0x68;
	buffer[313] = (uint8_t)pass_len;

	/* (pass_len) ror */
	ror(md5a, pass, pass_len, &buffer[314]);

	/* (2) 0x02 0x0c */
	memcpy(&buffer[314 + pass_len], "\x02\x0c", 2);

	/* (4) checksum2 */
	memcpy(&buffer[316 + pass_len], "\x01\x26\x07\x11\x00\x00", 6);
	memcpy(&buffer[322 + pass_len], mac, 6);
	checksum(buffer, 328 + pass_len, &buffer[316 + pass_len]);

	/* (2) zero */
	memset(&buffer[320 + pass_len], 0x00, 2);

	/* (6) mac */
	memcpy(&buffer[322 + pass_len], mac, 6);

	/* (3) zero*/

	/* (2) unknow */
	memcpy(&buffer[331 + pass_len], "\x6e\xe2", 2);

	return (333 + (int)pass_len);
}

void keepalive_build(int type, long ran)
{
	if (type == 0)
	{
		buffer[0] = 0xff;
		memcpy(&buffer[1], md5a, 16);
		memset(&buffer[17], 0x00, 3);
		memcpy(&buffer[20], tail, 16);
		buffer[36] = (uint8_t)(ran >> 8);
		buffer[37] = (uint8_t)(ran);
	} else {
		memset(buffer, 0x00, 40);
		buffer[0] = 0x07;
		buffer[1] = (uint8_t)(alivesum %= 32);
		buffer[2] = 0x28;
		buffer[3] = 0x00;
		buffer[4] = 0x0b;
		buffer[5] = (uint8_t)(2 * type - 1);
		memcpy(&buffer[6], keepaliveVer, 2);
		buffer[9] = (uint8_t)(ran >> 8);
		buffer[10] = (uint8_t)(ran);
		memcpy(&buffer[16], flux, 4);
		if (type == 2)
			memcpy(&buffer[28], &ip, 4);
	}
}

void readArgs(int argc, char *argv[])
{
	int opt = 0;
	const char optString[] = "dc:dvh";
	while ((opt = getopt(argc, argv, optString)) != EOF)
	{
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 'c':
			fileConf = optarg;
			break;
		case 'v':
		case 'h':
			printf("%s", README);
			exit(EXIT_SUCCESS);
		}
	}
}

int getmac(in_addr_t addr, uint8_t* mac)
{
	struct ifconf ifc;
	struct ifreq *ifr;
	int i, nInterfaces;

	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_buf = (char*)buffer;

	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
	{
		perror("ioctl(SIOCGIFCONF)");
		return 1;
	}

	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / (int)sizeof(struct ifreq);
	for (i = 0; i < nInterfaces; i++)
	{
		struct ifreq* item = &ifr[i];

		if (((struct sockaddr_in *)&item->ifr_addr)
			->sin_addr.s_addr != addr)
			continue;

		/* Get the MAC address */
		if (ioctl(sock, SIOCGIFHWADDR, item) < 0)
		{
			perror("ioctl(SIOCGIFHWADDR)");
			break;
		} else {
			memcpy(mac, item->ifr_hwaddr.sa_data, 6);
			return 0;
		}
	}
	return 1;
}

int readmac(const char* data, uint8_t* mac)
{
	return sscanf(data, macFormat, &mac[0], &mac[1],
		&mac[2], &mac[3], &mac[4], &mac[5]) != 6;
}

void ror(const uint8_t* md5a, const char* pass, size_t len, uint8_t* to)
{
	int i, x, r;
	for (i = 0; i < len; i++)
	{
		x = md5a[i] ^ pass[i];
		r = (x << 3) + (x >> 5);
		to[i] = (uint8_t)r;
	}
}

void checksum(const uint8_t* buffer, size_t len, uint8_t* to)
{
	union {
		uint32_t uni;
		uint8_t arr[4];
	} reverse;

	int i; uint32_t sum = 1234;
	for (i = 0; i + 4 <= len; i += 4) {
		memcpy(reverse.arr, &buffer[i], 4);
		sum ^= reverse.uni;
	}
	if (i < len)
	{
		memset(reverse.arr, 0x00, 4);
		memcpy(reverse.arr, &buffer[i], (size_t)(len - i));
		sum ^= reverse.uni;
	}
	sum = (1968 * sum);
	memcpy(to, &sum, 4);
}

int readConf(const char file[])
{
	FILE *pconf = fopen(file, "r");
	if (pconf == NULL) {
		perror(file);
		return -1;
	}

	//size_t i, len;
	char *cmd, *arg, *chr;
	struct conf* i;

	while (fgets(buffer, sizeof(buffer), pconf) != NULL) {
		cmd = buffer;
		if (*cmd == '#' || *cmd == 0) continue;
		chr = strchr(cmd, '#');
		while (chr != NULL) {
			if (isspace(*(chr - 1))) {
				*chr = '\0'; break;
			}
			chr = strchr(chr + 1, '#');
		}

		for (; isspace(*cmd); cmd++);
		if (*cmd == 0) continue;

		for (arg = cmd; !isspace(*arg); arg++);
		*(arg++) = '\0';

		for (i = confs; i->option != NULL; i++) {
			if (strcasecmp(cmd, i->option) == 0)
				break;
		}

		if (i->option == NULL)
		{
			fprintf(stderr, "%s: unrecognized command \"%s\". \n", file, cmd);
			continue;
		}

		for (; isspace(*arg); arg++);
		if (*arg == 0) continue;

		chr = arg + strlen(arg) - 1;
		for (; isspace(*chr); chr--)
			*chr = '\0';
		
		//free(i->value);
		strcpy(i->value, arg);
	}

	fclose(pconf);
	return 0;
}
