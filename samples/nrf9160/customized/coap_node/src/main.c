/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <lte_lc.h>
#include <at_cmd.h>
#include "test_config.h"


#define APP_COAP_VERSION 1
#define NUM_PENDINGS     3


static int sock;
static struct pollfd fds;
static struct sockaddr_storage server;
static u16_t next_token;

static u8_t coap_buf[TEST_CONFIG_MAX_MSG_LEN_BYTE];
/* Request Time and Data */
static const char timestamp[] = "AT+CCLK?";
static char cclk_buf[200];
static struct k_delayed_work retransmit_work;
static struct coap_pending pendings[NUM_PENDINGS];

#if defined(CONFIG_BSD_LIBRARY)

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
	printk("bsdlib recoverable error: %u\n", err);
}

/**@brief Irrecoverable BSD library error. */
void bsd_irrecoverable_error_handler(uint32_t err)
{
	printk("bsdlib irrecoverable error: %u\n", err);

	__ASSERT_NO_MSG(false);
}

#endif /* defined(CONFIG_BSD_LIBRARY) */

static void print_timestamp(void)
{
	int err = 0;
	err = at_cmd_write(timestamp,
		 cclk_buf,
		 sizeof(cclk_buf),
		 NULL);
	if ( err == 0 )
	{
		printk("Timestamp: %s", cclk_buf);
	}
	else
	{
		printk("CCLK failed!\n");
	}
}

static void retransmit_request(struct k_work *work)
{
	struct coap_pending *pending;

	pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return;
	}

	if (!coap_pending_cycle(pending)) {
		k_free(pending->data);
		coap_pending_clear(pending);
		return;
	}

	k_delayed_work_submit(&retransmit_work, pending->timeout);
}

static int create_pending_request(struct coap_packet *response,
				  const struct sockaddr *addr, struct coap_pending *p_pending)
{
	struct coap_pending *pending;
	int r;

	p_pending = coap_pending_next_unused(pendings, NUM_PENDINGS);
	if (!p_pending) {
		return -ENOMEM;
	}

	r = coap_pending_init(p_pending, response, addr);
	if (r < 0) {
		return -EINVAL;
	}

	coap_pending_cycle(p_pending);

	pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return 0;
	}

	k_delayed_work_submit(&retransmit_work, pending->timeout);

	return 0;
}

/**@brief Resolves the configured hostname. */
static int server_resolve(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM
	};
	/* IPv4 Address. */
	struct sockaddr_in *server4 = ((struct sockaddr_in *)&server);
	char ipv4_addr[NET_IPV4_ADDR_LEN];

	err = getaddrinfo(CONFIG_COAP_SERVER_HOSTNAME, NULL, &hints, &result);

	if (err == 0 && result != NULL)
	{
		server4->sin_addr.s_addr =
		((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
	}
	else
	{
		inet_pton(AF_INET, "128.39.37.167", &(server4->sin_addr));
	} 

	if (err != 0) {
		printk("ERROR: getaddrinfo failed %d\n", err);
	}

	if (result == NULL) {
		printk("ERROR: Address not found\n");
	}
	
	server4->sin_family = AF_INET;
	server4->sin_port = htons(CONFIG_COAP_SERVER_PORT);

	inet_ntop(AF_INET, &server4->sin_addr.s_addr, ipv4_addr,
		  sizeof(ipv4_addr));
	printk("IPv4 Address found %s\n", ipv4_addr);

	/* Free the address. */
	freeaddrinfo(result);

	return 0;
}

/**@brief Initialize the CoAP client */
static int client_init(void)
{
	int err;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		printk("Failed to create CoAP socket: %d.\n", errno);
		return -errno;
	}

	err = connect(sock, (struct sockaddr *)&server,
		      sizeof(struct sockaddr_in));
	if (err < 0) {
		printk("Connect failed : %d\n", errno);
		return -errno;
	}

	/* Initialize FDS, for poll. */
	fds.fd = sock;
	fds.events = POLLIN;

	/* Randomize token. */
	next_token = sys_rand32_get();

	return 0;
}

/**@brief Handles responses from the remote CoAP server. */
static int client_handle_get_response(u8_t *buf, int received)
{
	int err;
	struct coap_packet reply;
	struct coap_pending *pending;
	const u8_t *payload;
	u16_t payload_len;
	u8_t token[8];
	u16_t token_len;
	u8_t temp_buf[16];
	u8_t type;

	err = coap_packet_parse(&reply, buf, received, NULL, 0);
	if (err < 0) {
		printk("Malformed response received: %d\n", err);
		return err;
	}

	payload = coap_packet_get_payload(&reply, &payload_len);
	token_len = coap_header_get_token(&reply, token);

	if ((token_len != sizeof(next_token)) &&
	    (memcmp(&next_token, token, sizeof(next_token)) != 0)) {
		printk("Invalid token received: 0x%02x%02x\n",
		       token[1], token[0]);
		return 0;
	}

	type = coap_header_get_type(&reply);

	pending = coap_pending_received(&reply, pendings, NUM_PENDINGS);
	if (pending) {
		/* Clear CoAP pending request */
		if (type == COAP_TYPE_ACK) {
			k_free(pending->data);
			coap_pending_clear(pending);
		}
	}

	snprintf(temp_buf, MAX(payload_len, sizeof(temp_buf)), "%s", payload);

	printk("CoAP response: code: 0x%x, type: %d, token 0x%02x%02x, payload: %s\n",
	       coap_header_get_code(&reply), type, token[1], token[0], temp_buf);

	return 0;
}

/**@biref Send CoAP POST request. */
static int client_get_send(void)
{
	int err;
	u8_t *data;
	struct coap_packet request;
	struct coap_pending pending;

	data = (u8_t *)k_malloc(TEST_CONFIG_MAX_MSG_LEN_BYTE);
	if (!data) {
		return -ENOMEM;
	}

	next_token++;

	err = coap_packet_init(&request, data, TEST_CONFIG_MAX_MSG_LEN_BYTE,
			       APP_COAP_VERSION, TEST_CONFIG_COAP_TYPE,
			       sizeof(next_token), (u8_t *)&next_token,
			       TEST_CONFIG_COAP_METHOD, coap_next_id());
	if (err < 0) {
		printk("Failed to create CoAP request, %d\n", err);
		goto end;
	}

	err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					(u8_t *)CONFIG_COAP_RESOURCE,
					strlen(CONFIG_COAP_RESOURCE));
	if (err < 0) {
		printk("Failed to encode CoAP option, %d\n", err);
		goto end;
	}

	if (TEST_CONFIG_COAP_TYPE == COAP_TYPE_CON) {
		err = create_pending_request(&request, (struct sockaddr *)&server, &pending);
		if (err < 0) {
			printk("Failed to create pending request, %d\n", err);
			goto end;
		}
	}

	err = send(sock, request.data, request.offset, 0);

	if (TEST_CONFIG_COAP_TYPE == COAP_TYPE_CON ){
		if ( err < 0 )
		{
			printk("Failed to send CoAP request, %d\n", errno);
			k_free(data);
			coap_pending_clear(&pending);
		}
		else
		{
			printk("CoAP request sent: token 0x%04x, len:%d\n", next_token, sizeof(coap_buf));
		}
		return err;
	}

end:
	k_free(data);

	return err;
}

/**@brief Configures modem to provide LTE link. Blocks until link is
 * successfully established.
 */
static void modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already turned on
		 * and connected.
		 */
	} else {
		int err;

		printk("LTE Link Connecting ...\n");
		err = lte_lc_init_and_connect();
		__ASSERT(err == 0, "LTE link could not be established.");
		printk("LTE Link Connected!\n");
	}
#endif
}

/* Returns 0 if data is available.
 * Returns -EAGAIN if timeout occured and there is no data.
 * Returns other, negative error code in case of poll error.
 */
static int wait_and_rcv(int timeout)
{
	int err = 0, received;
	int ret = poll(&fds, 1, timeout);

	if (ret < 0) {
		printk("poll error: %d\n", errno);
		return -errno;
	}

	if (ret == 0) {
		/* Timeout. */
		return 0;
	}

	if ((fds.revents & POLLIN) == POLLIN) 
	{
		received = recv(sock, coap_buf, sizeof(coap_buf), MSG_DONTWAIT);
		if (received < 0) {
			if ( !(errno == EAGAIN || errno == EWOULDBLOCK) ) {
				printk("Socket error, exit...\n");
				return -errno;
			}
		}

		if (received > 0) {
			err = client_handle_get_response(coap_buf, received);
			if (err < 0) {
				printk("Invalid response, exit...\n");
				return err;
			}
		}

		return 0;
	}

	if ((fds.revents & POLLERR) == POLLERR) {
		printk("wait: POLLERR\n");
		return -EIO;
	}

	if ((fds.revents & POLLNVAL) == POLLNVAL) {
		printk("wait: POLLNVAL\n");
		return -EBADF;
	}

	return -EAGAIN;
}

static int send_burst(uint32_t pck_nr, uint16_t pck_itt)
{
	s64_t next_msg_time    = pck_itt;
	uint8_t nr_of_pck_sent = 0;  // To keep record of nr of packets sent in a burst
	int err = 0;

	next_msg_time = k_uptime_get();

	while ( nr_of_pck_sent < pck_nr ) 
	{
		if (k_uptime_get() >= next_msg_time) {
			err = client_get_send();
			if (err != 0) {
				printk("Failed to send GET request, exit...\n");
				break;
			}

			next_msg_time += pck_itt;
			nr_of_pck_sent++;
		}

		s64_t remaining = next_msg_time - k_uptime_get();

		if (remaining < 0) {
			remaining = 0;
		}

		err = wait_and_rcv(remaining);
		if (err != 0) {
			break;
		}
	}

	return err;

}

void main(void)
{
	int err = 0;
	int nr_of_runs = 0;

	print_timestamp();

	printk("The nRF CoAP client sample started\n");

	modem_configure();

	if (server_resolve() != 0) {
		printk("Failed to resolve server name\n");
		return;
	}

	if (client_init() != 0) {
		printk("Failed to initialize CoAP client\n");
		return;
	}

	k_delayed_work_init(&retransmit_work, retransmit_request);

	while ( nr_of_runs < TEST_CONFIG_NR_OF_TEST_RUN )
	{
		err = send_burst(TEST_CONFIG_PCK_NR_IN_BURST, TEST_CONFIG_PCK_ITT_MS); // Send 10 packets with 5s itt
		if (err != 0)
		{
			break;
		}

		if ( wait_and_rcv(TEST_CONFIG_SEND_INTERVAL_MS) != 0 )
		{
			break;
		}

		nr_of_runs++;
	}
	

	(void)close(sock);
}
