/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <linux/if.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/pagemap.h>
/* For sys_open & sys_close */
#include <linux/syscalls.h>
#include <net/sock.h>

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

#include <linux/inetdevice.h>

#ifndef HAVE_KERNEL_SETSOCKOPT
int kernel_setsockopt(struct socket *sock, int level, int optname,
			char *val, unsigned int optlen)
{
	sockptr_t optval = KERNEL_SOCKPTR(val);
	int err;

	if (level == SOL_SOCKET)
		err = sock_setsockopt(sock, level, optname, optval, optlen);
	else
		err = sock->ops->setsockopt(sock, level, optname, optval,
					    optlen);
	return err;
}
EXPORT_SYMBOL(kernel_setsockopt);
#endif

static int
lnet_sock_create_kern(struct socket **sock, struct net *ns)
{
	int rc;

#ifdef HAVE_SOCK_CREATE_KERN_USE_NET
	rc = sock_create_kern(ns, PF_INET, SOCK_STREAM, 0, sock);
#else
	rc = sock_create_kern(PF_INET, SOCK_STREAM, 0, sock);
#endif

	return rc;
}

int
lnet_ipif_query(char *name, int *up, __u32 *ip, __u32 *mask, struct net *ns)
{
	struct net_device *dev;
	struct in_device *in_dev;
	const struct in_ifaddr *ifa;
	unsigned int flags;
	char *colon, *ifname;
	int ret;
	size_t slen;

	/*
	 * Copy the interface name, since we may be about to modify it.
	 */
	slen = strlen(name) + 1;
	ifname = kzalloc(slen, GFP_KERNEL);
	if (ifname == NULL)
		return -ENOMEM;

	memcpy(ifname, name, slen);
	colon = strchr(ifname, ':');
	if (colon)
		*colon = 0;

	dev_load(ns, ifname);
	ret = -ENODEV;

	rtnl_lock();

	dev = __dev_get_by_name(ns, ifname);

	if (colon)
		*colon = ':';

	if (dev == NULL) {
		CERROR("Can't find interface %s\n", name);
		goto out;
	}

	flags = dev_get_flags(dev);
	if ((flags & IFF_UP) == 0) {
		CDEBUG(D_NET, "Interface %s down\n", name);
		*up = 0;
		*ip = *mask = 0;
		ret = 0;
		goto out;
	}

	/*
	 * Only support IPv4, so just walk the list of IPv4 assigned
	 * addresses to a device.
	 */
	in_dev = __in_dev_get_rtnl(dev);

	in_dev_for_each_ifa_rtnl(ifa, in_dev) {
		if (!strcmp(ifa->ifa_label, ifname))
			break;
	}

	if (ifa != NULL) {
		*up = 1;
		*mask = ntohl(ifa->ifa_mask);
		*ip = ntohl(ifa->ifa_local);
		ret = 0;
	} else {
		CERROR("Can't get mask/ip for interface %s\n", name);
	}

out:
	rtnl_unlock();
	kfree(ifname);
	return ret;
}
EXPORT_SYMBOL(lnet_ipif_query);

void
lnet_ipif_free_enumeration(char **names, int n)
{
	LIBCFS_FREE(names, PAGE_SIZE / IFNAMSIZ);
	LIBCFS_FREE(names[0], PAGE_SIZE);
}
EXPORT_SYMBOL(lnet_ipif_free_enumeration);

int
lnet_ipif_enumerate(char ***namesp, struct net *ns)
{
	char **names;
	char *space;
	const struct in_ifaddr *ifa;
	struct net_device *dev;
	struct in_device *in_dev;
	int maxifs, nifs, toobig;
	size_t used, slen;

	maxifs = PAGE_SIZE / IFNAMSIZ;
	nifs = 0;
	used = 0;
	toobig = 0;

	/*
	 * For simplicity, just allocate the maximum number of names
	 * that can be dealt with. The free function will ignore the
	 * arg
	 */
	LIBCFS_ALLOC(names, maxifs * sizeof (*names));
	if (names == NULL)
		return -ENOMEM;

	LIBCFS_ALLOC(space, PAGE_SIZE);
	if (space == NULL) {
		LIBCFS_FREE(names, maxifs * sizeof (*names));
		return -ENOMEM;
	}

	/*
	 * Only IPv4 is supported, so just loop all network
	 * devices, and loop the IPv4 interfaces (addresses)
	 * assigned to each device.
	 */
	rtnl_lock();
	for_each_netdev(ns, dev) {
		in_dev = __in_dev_get_rtnl(dev);
		if (!in_dev)
			continue;

		in_dev_for_each_ifa_rtnl(ifa, in_dev) {
			nifs++;
			if (toobig)
				continue;

			if (nifs > maxifs) {
				toobig = 1;
				continue;
			}

			slen = strlen(ifa->ifa_label) + 1;
			if (used + slen > PAGE_SIZE) {
				toobig = 1;
				continue;
			}
			memcpy(space + used, ifa->ifa_label, slen);
			names[nifs - 1] = space + used;
			used += slen;
		}
	}
	rtnl_unlock();

	*namesp = names;

	return nifs;
}
EXPORT_SYMBOL(lnet_ipif_enumerate);

int
lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = cfs_time_seconds(timeout);
	unsigned long then;

	LASSERT(nob > 0);
	/* Caller may pass a zero timeout if she thinks the socket buffer is
	 * empty enough to take the whole message immediately */

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= (timeout == 0) ? MSG_DONTWAIT : 0
		};

		if (timeout != 0) {
			struct sock *sk = sock->sk;

			lock_sock(sk);
			sk->sk_sndtimeo = jiffies_left;
			release_sock(sk);
		}

		then = jiffies;
		rc = kernel_sendmsg(sock, &msg, &iov, 1, nob);
		jiffies_left -= jiffies - then;

		if (rc == nob)
			return 0;

		if (rc < 0)
			return rc;

		if (rc == 0) {
			CERROR("Unexpected zero rc\n");
			return -ECONNABORTED;
		}

		if (jiffies_left <= 0)
			return -EAGAIN;

		buffer = ((char *)buffer) + rc;
		nob -= rc;
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_write);

int
lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = cfs_time_seconds(timeout);
	unsigned long then;

	LASSERT(nob > 0);
	LASSERT(jiffies_left > 0);

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= 0
		};
		struct sock *sk = sock->sk;

		/* Set receive timeout to remaining time */
		lock_sock(sk);
		sk->sk_rcvtimeo = jiffies_left;
		release_sock(sk);

		then = jiffies;
		rc = kernel_recvmsg(sock, &msg, &iov, 1, nob, 0);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (rc == 0)
			return -ECONNRESET;

		buffer = ((char *)buffer) + rc;
		nob -= rc;

		if (nob == 0)
			return 0;

		if (jiffies_left <= 0)
			return -ETIMEDOUT;
	}
}
EXPORT_SYMBOL(lnet_sock_read);

static int
lnet_sock_create(struct socket **sockp, int *fatal,
		 __u32 local_ip, int local_port, struct net *ns)
{
	struct sockaddr_in  locaddr;
	struct socket	   *sock;
	int		    rc;
	int		    option;

	/* All errors are fatal except bind failure if the port is in use */
	*fatal = 1;

	rc = lnet_sock_create_kern(&sock, ns);
	*sockp = sock;
	if (rc != 0) {
		CERROR("Can't create socket: %d\n", rc);
		return rc;
	}

	option = 1;
	rc = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&option, sizeof(option));
	if (rc != 0) {
		CERROR("Can't set SO_REUSEADDR for socket: %d\n", rc);
		goto failed;
	}

	if (local_ip != 0 || local_port != 0) {
		memset(&locaddr, 0, sizeof(locaddr));
		locaddr.sin_family = AF_INET;
		locaddr.sin_port = htons(local_port);
		locaddr.sin_addr.s_addr = (local_ip == 0) ?
					  INADDR_ANY : htonl(local_ip);

		rc = kernel_bind(sock, (struct sockaddr *)&locaddr,
				 sizeof(locaddr));
		if (rc == -EADDRINUSE) {
			CDEBUG(D_NET, "Port %d already in use\n", local_port);
			*fatal = 0;
			goto failed;
		}
		if (rc != 0) {
			CERROR("Error trying to bind to port %d: %d\n",
			       local_port, rc);
			goto failed;
		}
	}
	return 0;

failed:
	sock_release(sock);
	return rc;
}

int
lnet_sock_setbuf(struct socket *sock, int txbufsize, int rxbufsize)
{
	int		    option;
	int		    rc;

	if (txbufsize != 0) {
		option = txbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set send buffer %d: %d\n",
				option, rc);
			return rc;
		}
	}

	if (rxbufsize != 0) {
		option = rxbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set receive buffer %d: %d\n",
				option, rc);
			return rc;
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_setbuf);

int
lnet_sock_getaddr(struct socket *sock, bool remote, __u32 *ip, int *port)
{
	struct sockaddr_in sin;
	int rc;
#ifndef HAVE_KERN_SOCK_GETNAME_2ARGS
	int len = sizeof(sin);
#endif

	if (remote)
		rc = lnet_kernel_getpeername(sock,
					     (struct sockaddr *)&sin, &len);
	else
		rc = lnet_kernel_getsockname(sock,
					     (struct sockaddr *)&sin, &len);
	if (rc < 0) {
		CERROR("Error %d getting sock %s IP/port\n",
			rc, remote ? "peer" : "local");
		return rc;
	}

	if (ip != NULL)
		*ip = ntohl(sin.sin_addr.s_addr);

	if (port != NULL)
		*port = ntohs(sin.sin_port);

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getaddr);

int
lnet_sock_getbuf(struct socket *sock, int *txbufsize, int *rxbufsize)
{
	if (txbufsize != NULL)
		*txbufsize = sock->sk->sk_sndbuf;

	if (rxbufsize != NULL)
		*rxbufsize = sock->sk->sk_rcvbuf;

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getbuf);

int
lnet_sock_listen(struct socket **sockp,
		   __u32 local_ip, int local_port, int backlog, struct net *ns)
{
	int	 fatal;
	int	 rc;

	rc = lnet_sock_create(sockp, &fatal, local_ip, local_port, ns);
	if (rc != 0) {
		if (!fatal)
			CERROR("Can't create socket: port %d already in use\n",
			       local_port);
		return rc;
	}

	rc = kernel_listen(*sockp, backlog);
	if (rc == 0)
		return 0;

	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(*sockp);
	return rc;
}

#ifndef HAVE_SK_SLEEP
static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	return sk->sk_sleep;
}
#endif

int
lnet_sock_accept(struct socket **newsockp, struct socket *sock)
{
	wait_queue_entry_t wait;
	struct socket *newsock;
	int	       rc;

	/* XXX this should add a ref to sock->ops->owner, if
	 * TCP could be a module */
	rc = sock_create_lite(PF_PACKET, sock->type, IPPROTO_TCP, &newsock);
	if (rc) {
		CERROR("Can't allocate socket\n");
		return rc;
	}

	newsock->ops = sock->ops;

#ifdef HAVE_KERN_SOCK_ACCEPT_FLAG_ARG
	rc = sock->ops->accept(sock, newsock, O_NONBLOCK, false);
#else
	rc = sock->ops->accept(sock, newsock, O_NONBLOCK);
#endif
	if (rc == -EAGAIN) {
		/* Nothing ready, so wait for activity */
		init_waitqueue_entry(&wait, current);
		add_wait_queue(sk_sleep(sock->sk), &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		remove_wait_queue(sk_sleep(sock->sk), &wait);
#ifdef HAVE_KERN_SOCK_ACCEPT_FLAG_ARG
		rc = sock->ops->accept(sock, newsock, O_NONBLOCK, false);
#else
		rc = sock->ops->accept(sock, newsock, O_NONBLOCK);
#endif
	}

	if (rc != 0)
		goto failed;

	*newsockp = newsock;
	return 0;

failed:
	sock_release(newsock);
	return rc;
}

int
lnet_sock_connect(struct socket **sockp, int *fatal,
		  __u32 local_ip, int local_port,
		  __u32 peer_ip, int peer_port,
		  struct net *ns)
{
	struct sockaddr_in  srvaddr;
	int		    rc;

	rc = lnet_sock_create(sockp, fatal, local_ip, local_port, ns);
	if (rc != 0)
		return rc;

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(peer_port);
	srvaddr.sin_addr.s_addr = htonl(peer_ip);

	rc = kernel_connect(*sockp, (struct sockaddr *)&srvaddr,
			    sizeof(srvaddr), 0);
	if (rc == 0)
		return 0;

	/* EADDRNOTAVAIL probably means we're already connected to the same
	 * peer/port on the same local port on a differently typed
	 * connection.	Let our caller retry with a different local
	 * port... */
	*fatal = !(rc == -EADDRNOTAVAIL);

	CDEBUG_LIMIT(*fatal ? D_NETERROR : D_NET,
	       "Error %d connecting %pI4h/%d -> %pI4h/%d\n", rc,
	       &local_ip, local_port, &peer_ip, peer_port);

	sock_release(*sockp);
	return rc;
}
