/*
 * packet-uru.c
 * Routines for Uru dissection
 *
 * Copyright (C) 2005-2006  The Alcugs Project Server Team
 * Copyright (C) 2006-2010  a'moaca' and cjkelly1
 *
 * $Id: $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* 
 * http://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <gmodule.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/reassemble.h>
#include <epan/crypt/crypt-md5.h> /* for UU checksum validation */
#include <epan/timestamp.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/crypt/crypt-rc4.h>
#include <wsutil/file_util.h>
#ifdef HAVE_DIRENT_H
#include <dirent.h> /* be sure to include after wsutil/file_util.h */
#endif
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif
#include "uru-prot.h"
#include "uru-vaultstrs.h"
#include "uru-typecodes.h"
#include "urulive-typecodes.h"
#include "urulive-msg-typecodes.h"

/* Define this if you have the change from revision 31767 in your
   Wireshark tree. */
#undef HAVE_REASSEMBLED_LENGTH

#define EPHEMERAL_BUFS
#define RC4_CACHE_FREQ 40000 /* this should probably be tuned */

#ifndef HAVE_REASSEMBLED_LENGTH
/* In the trunk, winposixtype.h is gone. */
#ifdef _WIN32
#include <winposixtype.h>
#endif
#endif

#undef INCLUDE_ALL_TYPES /* undef this for non-development compiles */
#undef DEVELOPMENT /* undef this for non-development compiles */


/* Initialize the subtree pointers */
static gint ett_uru = -1;
static gint ett_header = -1;
static gint ett_netmsg = -1;
static gint ett_netmsgflags = -1;
static gint ett_members = -1;
static gint ett_agecontents = -1;
static gint ett_chatflags = -1;
static gint ett_inputflags = -1;
static gint ett_rel_occupied = -1;
static gint ett_rel_interesting = -1;
static gint ett_vault_manifest = -1;
static gint ett_vault_reflist = -1;
static gint ett_vault_nodelist = -1;
static gint ett_vault_nodes = -1;
static gint ett_vault_fullnode = -1;
static gint ett_sdl_entry = -1;
static gint ett_sdl_subsdl = -1;
static gint ett_mflags = -1;
static gint ett_uru_fragment = -1;
static gint ett_uru_fragments = -1;
/* Using several trees allows different subtrees to be kept open; 10
   may be overkill but oh well */
#define ODESC_OFFSET 20 /* increment this when adding new subtrees above */
#define ODESC_COUNT 10 /* increment this when adding new odesc subtrees */
static gint ett_odesc = -1;
static gint ett_odesc2 = -1;
static gint ett_odesc3 = -1;
static gint ett_odesc4 = -1;
static gint ett_odesc5 = -1;
static gint ett_odesc6 = -1;
static gint ett_odesc7 = -1;
static gint ett_odesc8 = -1;
static gint ett_odesc9 = -1;
static gint ett_odesc10 = -1;

/* Set up protocol subtree array */
static gint *ett[] = {
  &ett_uru,
  &ett_header,
  &ett_netmsg,
  &ett_netmsgflags,
  &ett_members,
  &ett_agecontents,
  &ett_chatflags,
  &ett_inputflags,
  &ett_rel_occupied,
  &ett_rel_interesting,
  &ett_vault_manifest,
  &ett_vault_reflist,
  &ett_vault_nodelist,
  &ett_vault_nodes,
  &ett_vault_fullnode,
  &ett_sdl_entry,
  &ett_sdl_subsdl,
  &ett_mflags,
  &ett_uru_fragment,
  &ett_uru_fragments,
  &ett_odesc,
  &ett_odesc2,
  &ett_odesc3,
  &ett_odesc4,
  &ett_odesc5,
  &ett_odesc6,
  &ett_odesc7,
  &ett_odesc8,
  &ett_odesc9,
  &ett_odesc10
};

/* we don't need to increment the argument to this if exists is 0 */
#define ETT_ODESC(n) ((n < ODESC_COUNT) ? (*(ett[ODESC_OFFSET+n])) : ett_odesc)


/* Initialize the protocol and registered fields */
static int proto_uru = -1;
#include "uru-hf.c"


/* Options */
/* port range logic borrowed from plugins/packet-asn1.c */
#define URU_PORT_LOW 5000
#define URU_PORT_HIGH 6000
static range_t *global_uru_port_range;
static range_t *uru_port_range;
static gboolean global_uru_header_style = TRUE;
static gboolean global_uru_summary_ack = FALSE;
static gboolean global_uru_parse_vault_streams = TRUE;
static gboolean global_uru_hide_stuff = TRUE;
static gboolean global_uru_load_sdls = TRUE;
static const char *global_uru_sdl_path = ".";
static dissector_handle_t uru_handle;

/* Fragment reassembly */
static GHashTable *uru_fragment_table = NULL;
static GHashTable *uru_reassembled_table = NULL;
/* global setting, used to retrofit UU dissection */
static gboolean islive = FALSE;

/* If we can deduce which protocol version is being used, this keeps track */
enum protocol_version { UNKNOWN, UU, POTS };
struct uru_conv {
  enum protocol_version version;
  guint sport;
  guint cport;
};
static struct uru_conv *curr_conv = NULL;

struct sdl_var {
  gint type;
  char *name;
  /* TODO: put in default values? */
  gint count;
};
struct sdl_struct {
  char *type;
  char *name;
  gint count;
  struct sdl_info *stype;
};
struct sdl_info {
  struct sdl_info *next; /* very simple list */
  guint version;
  char *name;
  guint varct;
  guint structct;
  struct sdl_var *vars;
  struct sdl_struct *structs;
};
static struct sdl_info *all_sdls = NULL;

/* Helper functions */
/* function copied from alcugs/trunk/src/unet/protocol/protocol.cpp */
/**
 Decodes the specific packet from Uru validation level 2
   k = offset MOD 8
   dec: x = c * 2 ^ (8-k) MOD 255
*/
void alcDecodePacket(unsigned char* buf, int n) {
        int i;
        for(i=0; i<n; i++) {
                buf[i] = buf[i] >> (i%8) | buf[i] << (8-(i%8));
        }
}

void alcDecodePacket2(unsigned char* buf, int n, int offset) {
        int i;
        for(i=0; i<n; i++) {
                buf[i] = buf[i] >> ((i+offset)%8) | buf[i] << (8-((i+offset)%8));
        }
}

static gint dissect_netmsg_flags(tvbuff_t *, gint, proto_tree *);
static gint dissect_plNetMessage(guint16, tvbuff_t *, gint, proto_tree *,
				 packet_info *);
static gint dissect_age_link(tvbuff_t *, gint, proto_tree *, gboolean);
static gint dissect_sdl_msg(tvbuff_t *, gint, proto_tree *, gint);
static gint recursively_dissect_sdl(tvbuff_t *, gint, proto_tree *,
				    gint, struct sdl_info *, gint);
static gint old_icky_heuristic_dissect_sdl(tvbuff_t *, gint, proto_tree *,
					   char *, gint);
static char * get_uru_string(tvbuff_t *, gint, guint *);
static char * get_uru_hexstring(tvbuff_t *, gint, guint *);
#define proto_tree_add_STR(t,h,b,o,l,s) \
    proto_tree_add_string(t, h, b, o, l, (s ? s : ""))
static void add_uru_timestamp(tvbuff_t *, gint, proto_tree *, int, int, int);
static void append_ts_formatted(proto_item *, guint32, guint32, gboolean);
static gint dissect_uru_object_subtree(tvbuff_t *, gint, proto_tree *,
				       int, char **, gboolean,
				       guint8 *, guint16 *, char **,
				       int, int, int);
static struct sdl_info * get_sdl_info(char *, guint16);
static gint add_sdl_by_type(tvbuff_t *, gint, proto_tree *, gint, int, gint);
static gint get_sdl_record(tvbuff_t *, gint, proto_tree *, gint, int,
			   guint8 *, gint *, gboolean *);
static void add_record_guess(tvbuff_t *, gint, proto_tree *, int);
static void add_record_array(tvbuff_t *, gint, proto_tree *, int);
static gint add_vault_node(tvbuff_t *, gint, proto_tree *, guint32 *);
static gint add_live_vault_node(tvbuff_t *, gint, proto_tree *);
static void append_uru_uuid(proto_item *, tvbuff_t *, gint);


#ifdef EPHEMERAL_BUFS
#define MAYBE_FREE(buf)
#define SBRK(tree, tvb, offset)
#else
#define MAYBE_FREE(buf) { if (buf) g_free(buf); }
#define SBRK(tree, tvb, offset) { proto_tree_add_text(tree, tvb, offset, 0, "sbrk: %u", sbrk(0)); }
#endif


/* Initialize the protocol and registered fields */
static int proto_urulive = -1;
static gint ett_urulive = -1;
static gint ett_manifest = -1;
static gint ett_agelist = -1;
static gint ett_livenetmsg = -1;

/* Set up protocol subtree array */
static gint *ett_live[] = {
  &ett_urulive,
  &ett_manifest,
  &ett_agelist,
  &ett_livenetmsg
};


/* Options */
static guint global_urulive_port = 14617;
static gboolean global_urulive_desegment = TRUE;
static gboolean global_urulive_showtcp = FALSE;
static gboolean global_urulive_detect_version = TRUE;
static gboolean global_urulive_is_pre4 = FALSE;
static gboolean global_urulive_is_encrypted = TRUE;
static gboolean global_urulive_is_v1 = FALSE;
static gboolean global_urulive_is_pre9 = FALSE;
struct rc4_key {
  guint32 server_port; /* ports in packet_info struct are guint32 */
  guint8 key[7];
};
static gboolean global_urulive_decrypt = FALSE;
/* use keys as configured */
static struct rc4_key *global_urulive_rc4_keys = NULL;
static gint global_urulive_n_rc4_keys = 0;
static const char *global_urulive_keys = "";
/* compute keys from private (server) key */
static gboolean global_urulive_use_private_keys = FALSE;
static const char *global_urulive_auth_file = "";
static const char *global_urulive_game_file = "";
#ifdef HAVE_LIBGCRYPT
static gcry_mpi_t auth_modulus = NULL, auth_exponent = NULL;
static gcry_mpi_t game_modulus = NULL, game_exponent = NULL;
#endif

static dissector_handle_t urulive_handle;

/* Fragment reassembly */
static GHashTable *urutcp_fragment_table = NULL;

#include "urulive-hf.c"

enum fourstate {
  NO_GUESS = 0,
  GUESS_YES = 1,
  CERTAIN_YES = 2,
  GUESS_NO = -1,
  CERTAIN_NO = -2
};
struct rc4_state_cache {
  rc4_state_struct s;
  guint32 seq;
};
struct urulive_conv {
  enum fourstate isdata;
  enum fourstate ispre4;
  /* sometime in versions 5-8 inclusive the message numbers changed */
  enum fourstate isv1;
  enum fourstate ispre9;
  enum fourstate isgame;
  /* MOULagain added "gatekeeper" */
  enum fourstate isgate;
  emem_tree_t *c2s_multisegment_pdus;
  emem_tree_t *s2c_multisegment_pdus;
  guint32 c2s_last_frame;
  guint32 s2c_last_frame;
  /* data for managing encrypted streams */
  gboolean negotiation_done;
  gboolean state_known;
  gboolean is_encrypted;
  guint32 c2s_crypt_zero; /* the sequence number of the first */
  guint32 s2c_crypt_zero; /* encrypted byte in the stream */
  struct rc4_state_cache c2s_next_state;
  struct rc4_state_cache s2c_next_state;
#ifdef HAVE_LIBGCRYPT
  guint8 key_half[8]; /* first byte true if we have the key */
#endif
  /* the following caches the RC4 crypto state every RC4_CACHE_FREQ bytes
     (approx.) so that packets can be re-decrypted later, out-of-order
     packets handled, etc. */
  emem_tree_t *c2s_rc4_states;
  emem_tree_t *s2c_rc4_states;
};

/* This used to have to be global because pinfo was not passed to
   get_urulive_message_len(), so it had to be set before calling
   tcp_dissect_pdus(), so it was set properly by the time
   dissect_urulive_message() was called.
   This is no longer true. We could clean up both globals if desired and
   compute them from pinfo in all functions. */
static gboolean isclient = FALSE;
/* Same deal for this. */
static struct urulive_conv *live_conv = NULL;

/* XXX This should be per-conversation, not global. */
static emem_tree_t *gameIDmap = NULL;

/* Helper functions */
static char * get_uru_widestring(tvbuff_t *, gint, guint *);
static char * get_widestring(tvbuff_t *, gint, guint *);
static proto_item * urulive_add_stringlen(proto_tree *, tvbuff_t *,
					  gint, int);
static void urulive_setup_crypto(guint32, guint32);
static void crypt_rc4_evolve(rc4_state_struct *, int);
static void urulive_decrypt(guint32, gboolean, guint8 *, int);
static struct rc4_key * find_rc4_key(guint32);
static guint16 get_v2_value(guint16);
static inline guint16 get_9_value(guint16, enum fourstate);
static guint16 live_translate(guint16);
static void desegment_urutcp(tvbuff_t *, packet_info *, proto_tree *,
			     emem_tree_t *);


/* Code to actually dissect the packets */
static void
dissect_uru(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti = NULL;
  proto_tree *uru_tree = NULL;

  gint offset = 0;
  tvbuff_t *ntvb, *rtvb;
  proto_item *tf;
  proto_tree *sub_tree = NULL;
  gboolean reassembled = FALSE;
  conversation_t *conv;

  guint8 packet_type;
  guint32 packetnum, seqnum, lastack, msglen;
  guint8 valtype, flags, fragnum, fragct, fragack;
  guint16 netmsgtype;

  packet_type = tvb_get_guint8(tvb, 0);
  if (packet_type == 0x3) {
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Uru");
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_clear(pinfo->cinfo, COL_INFO);
      if (pinfo->ptype == PT_UDP) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "%u->%u (%u)",
		     pinfo->srcport, pinfo->destport,
		     tvb_length_remaining(tvb, 0));
      }
      else {
	col_add_str(pinfo->cinfo, COL_INFO, "bad port type, not UDP");
      }
    }
  }
  else {
    return;
  }

  islive = FALSE;

  if (tree) { /* we are being asked for details */
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_uru, tvb, 0, -1, TRUE);
    uru_tree = proto_item_add_subtree(ti, ett_uru);
  }
  valtype = tvb_get_guint8(tvb, offset+1);
  if (valtype == 0) {
    if (tree) {
      tf = proto_tree_add_item(uru_tree, hf_uru_header, tvb, offset, 24, TRUE);
      sub_tree = proto_item_add_subtree(tf, ett_header);
      proto_tree_add_item(sub_tree, hf_uru_flag, tvb, offset, 1, TRUE);
      proto_tree_add_item(sub_tree, hf_uru_validation_type, tvb,
			   offset+1, 1, TRUE);
    }
    offset += 2;
    ntvb = tvb_new_subset(tvb, offset, -1, -1);
  }
  else if (valtype == 1 || valtype == 2) {
    guint32 chksum, bufsize;
    guint8 *newbuf;
/*
Don't fetch a little-endian value using "tvb_get_ntohs() or
"tvb_get_ntohl()" and then using "g_ntohs()", "g_htons()", "g_ntohl()",
or "g_htonl()" on the resulting value - the g_ routines in question
convert between network byte order (big-endian) and *host* byte order,
not *little-endian* byte order; not all machines on which Wireshark runs
are little-endian, even though PC's are.  Fetch those values using
"tvb_get_letohs()" and "tvb_get_letohl()".
*/
    if (tree) {
      tf = proto_tree_add_item(uru_tree, hf_uru_header, tvb, offset, 32, TRUE);
      sub_tree = proto_item_add_subtree(tf, ett_header);
      proto_tree_add_item(sub_tree, hf_uru_flag, tvb, offset, 1, TRUE);
      proto_tree_add_item(sub_tree, hf_uru_validation_type, tvb,
			  offset+1, 1, TRUE);
    }
    offset += 2;
    chksum = tvb_get_letohl(tvb, offset);
    if (tree) {
      proto_tree_add_uint(sub_tree, hf_uru_checksum, tvb, offset, 4, chksum);
      /* TODO: here verify the checksum */
      /* note business of swapping validation types!  ??? */
    }
    offset += 4;

    if (valtype == 2) {
      /* the rest of the packet is (might be?) encoded */
#ifdef yucky
      guint8 *newbuf2;
      bufsize = tvb_length_remaining(tvb, 0);
      newbuf = tvb_memdup(tvb, 0, bufsize);
      alcDecodePacket(newbuf, bufsize);
      newbuf2 = g_malloc(bufsize-offset);
      memcpy(newbuf2, newbuf+offset, bufsize-offset);
      g_free(newbuf);
      ntvb = tvb_new_real_data(newbuf2, bufsize-offset, bufsize-offset);
#else
      bufsize = tvb_length_remaining(tvb, offset);
      newbuf = tvb_memdup(tvb, offset, bufsize);
      alcDecodePacket2(newbuf, bufsize, offset);
      ntvb = tvb_new_real_data(newbuf, bufsize, bufsize);
#endif
      tvb_set_child_real_data_tvbuff(tvb, ntvb);
      add_new_data_source(pinfo, ntvb, "Decoded Data");
      tvb_set_free_cb(ntvb, g_free);
    }
    else {
      ntvb = tvb_new_subset(tvb, offset, -1, -1);
    }
  }
  else {
    /* shouldn't happen */
    if (tree) {
      proto_tree_add_uint_format(sub_tree, hf_uru_validation_type, tvb,
				 offset, 1, valtype,
				 "Unknown validation type %u", valtype);
    }
    return;
  }
  offset = 0;

  /* Uru header */
  packetnum = tvb_get_letohl(ntvb, offset);
  if (tree) {
    proto_tree_add_item(sub_tree, hf_uru_packetnum, ntvb, offset, 4, TRUE);
  }
  offset += 4;
  flags = tvb_get_guint8(ntvb, offset);
  if (tree) {
    proto_tree_add_item(sub_tree, hf_uru_msgtype, ntvb, offset, 1, TRUE);
  }
  offset += 1;
  if (!(flags & UNetExt)) {
    if (tree) {
      guint32 unk;
      unk = tvb_get_letohl(ntvb, offset);
      tf = proto_tree_add_item(sub_tree, hf_uru_unkA, ntvb, offset, 4, TRUE);
      if (global_uru_hide_stuff && unk == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
    }
    offset += 4;
  }
  fragnum = tvb_get_guint8(ntvb, offset);
  seqnum = tvb_get_letoh24(ntvb, offset+1);
  if (tree) {
    proto_tree_add_item(sub_tree, hf_uru_fragnum, ntvb, offset, 1, TRUE);
    proto_tree_add_item(sub_tree, hf_uru_msgnum, ntvb, offset+1, 3, TRUE);
  }
  offset += 4;
  fragct = tvb_get_guint8(ntvb, offset);
  if (tree) {
    proto_tree_add_item(sub_tree, hf_uru_fragct, ntvb, offset, 1, TRUE);
  }
  offset += 1;
  if (!(flags & UNetExt)) {
    if (tree) {
      guint32 unk;
      unk = tvb_get_letohl(ntvb, offset);
      tf = proto_tree_add_item(sub_tree, hf_uru_unkB, ntvb, offset, 4, TRUE);
      if (global_uru_hide_stuff && unk == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
    }
    offset += 4;
  }
  fragack = tvb_get_guint8(ntvb, offset);
  lastack = tvb_get_letoh24(ntvb, offset+1);
  if (tree) {
    proto_tree_add_item(sub_tree, hf_uru_fragack, ntvb, offset, 1, TRUE);
    proto_tree_add_item(sub_tree, hf_uru_lastack, ntvb, offset+1, 3, TRUE);
  }
  offset += 4;
  msglen = tvb_get_letohl(ntvb, offset);
  if (tree) {
    tf = proto_tree_add_item(sub_tree, hf_uru_msglen, ntvb, offset, 4, TRUE);
    if (flags == UNetAckReply) {
      if ((gint)(2+(16*msglen)) != tvb_length_remaining(ntvb, offset+4)) {
	if (tvb_length_remaining(ntvb, offset+4) > 2) {
	  proto_item_append_text(tf, " [incorrect, actual: %u]",
				 (tvb_length_remaining(ntvb, offset+4)-2)/4);
	  tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					     ntvb, offset, 4, 1,
					     "Message length incorrect");
	}
	else {
	  proto_item_append_text(tf, " [too short]");
	  tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					     ntvb, offset, 4, 1,
					     "Ack message too short");
	}
	PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    else if ((gint)msglen != tvb_length_remaining(ntvb, offset+4)) {
      proto_item_append_text(tf, " [incorrect, actual: %u]",
			     tvb_length_remaining(ntvb, offset+4));
      tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					 ntvb, offset, 4, 1,
					 "Message length incorrect");
      PROTO_ITEM_SET_GENERATED(tf);
    }
  }
  offset += 4;
  /* end of header */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    if (global_uru_summary_ack) {
      if (global_uru_header_style) {
	col_append_fstr(pinfo->cinfo,
			COL_INFO, "  [%u] ->%02X<- {%u,%u (%u) %u,%u}",
			packetnum, flags,
			seqnum, fragnum, fragct, lastack, fragack);
      }
      else {
	col_append_fstr(pinfo->cinfo,
			COL_INFO, "  0x%02X seq:%u(%u/%u) prev:%u(%u)",
			flags,
			seqnum, fragnum, fragct, lastack, fragack);
      }
    }
    else {
      if (global_uru_header_style) {
	col_append_fstr(pinfo->cinfo, COL_INFO, "  ->%02X<-", flags);
      }
      else {
	col_append_fstr(pinfo->cinfo, COL_INFO, "  0x%02X", flags);
      }
    }
  }

  /* Set up the conversation stuff */
  conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			   pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  if (!conv) {
    conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  }
  curr_conv = (struct uru_conv *)conversation_get_proto_data(conv, proto_uru);
  if (!curr_conv) {
    curr_conv = (struct uru_conv*)se_alloc(sizeof(struct uru_conv));
    curr_conv->version = UNKNOWN;
    curr_conv->sport = curr_conv->cport = 0;
    conversation_add_proto_data(conv, proto_uru, (void *)curr_conv);
  }

  /* Handle fragments */
  /* code from:
     http://www.wireshark.org/docs/wsdg_html_chunked/ChDissectReassemble.html */
  if (fragct != 0) {
    gboolean save_fragmented;
    tvbuff_t* new_tvb = NULL;
    fragment_data *frag_msg = NULL;

    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_msg = fragment_add_seq_check(ntvb, offset, pinfo,
		seqnum, /* ID for fragments belonging together */
		uru_fragment_table, /* list of message fragments */
		uru_reassembled_table, /* list of reassembled messages */
		fragnum, /* fragment sequence number */
		tvb_length_remaining(ntvb, offset), /* fragment length - to the end */
		fragnum != fragct); /* More fragments? */

    new_tvb = process_reassembled_data(ntvb, offset, pinfo,
		"Reassembled Message", frag_msg, &uru_frag_items,
		NULL, sub_tree);

    if (frag_msg) { /* Reassembled */
      if (check_col(pinfo->cinfo, COL_INFO))
	col_append_str(pinfo->cinfo, COL_INFO, 
		       " [Message Reassembled]");
    } else { /* Not last packet of reassembled Short Message */
      if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO,
			" [Message fragment %u]", fragnum);
    }

    if (new_tvb) { /* take it all */
      rtvb = new_tvb;
      /* their code: (none) */
      offset = 0;
      reassembled = TRUE;
    } else { /* make a new subset */
      /* their code: rtvb = tvb_new_subset(ntvb, offset, -1, -1); */
      rtvb = ntvb;
    }
    pinfo->fragmented = save_fragmented;
  }
  else { /* Not fragmented */
    /* their code: rtvb = tvb_new_subset(ntvb, offset, -1, -1); */
    rtvb = ntvb;
  }

  if (flags == (UNetNegotiation|UNetAckReq)) {
    /* a negotiation message */
    if (tree) {
      proto_item_append_text(ti, ", Negotiation");
      proto_tree_add_item(uru_tree, hf_uru_bandwidth, rtvb, offset, 4, TRUE);
      offset += 4;
      add_uru_timestamp(rtvb, offset, uru_tree,
			hf_uru_nego_ts, hf_uru_nego_sec, hf_uru_nego_usec);
      offset += 8;
    }
  }
  else if (flags == UNetAckReply) {
    /* an ack message */
    if (tree) {
      guint i;
      guint32 sn, snf;
      guint8 frn, frnf;
      guint32 zeros;

      proto_item_append_text(ti, ", Ack");
      zeros = tvb_get_letohs(rtvb, offset);
      if (zeros != 0) {
	proto_tree_add_boolean_format(uru_tree, hf_uru_incomplete_dissection,
				      rtvb, offset, 2, 1,
				      "Unknown data in Ack (%04X)", zeros);
      }
      else {
	tf = proto_tree_add_uint_format_value(uru_tree, hf_uru_ack_zero,
					      rtvb, offset, 2, 0, "0");
	if (global_uru_hide_stuff) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
      }
      offset += 2;
      for (i = 0; i < msglen; i++) {
	frn = tvb_get_guint8(rtvb, offset);
	tf = proto_tree_add_item(uru_tree, hf_uru_ack_frn, rtvb, offset,
				 1, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	sn = tvb_get_letoh24(rtvb, offset+1);
	tf = proto_tree_add_item(uru_tree, hf_uru_ack_sn, rtvb, offset+1,
				 3, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	zeros = tvb_get_letohl(rtvb, offset+4);
	if (zeros != 0) {
	  proto_tree_add_boolean_format(uru_tree, hf_uru_incomplete_dissection,
					rtvb, offset+4, 4, 1,
					"Unknown data in Ack (%08X)", zeros);
	}
	else {
	  /* we could add this to the tree, but we'd always hide it because we
	     hide the other ack parts (frn, sn, frnf, snf), so why bother? */
	}
	frnf = tvb_get_guint8(rtvb, offset+8);
	tf = proto_tree_add_item(uru_tree, hf_uru_ack_frnf, rtvb, offset+8,
				 1, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	snf = tvb_get_letoh24(rtvb, offset+9);
	tf = proto_tree_add_item(uru_tree, hf_uru_ack_snf, rtvb, offset+9,
				 3, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	zeros = tvb_get_letohl(rtvb, offset+12);
	if (zeros != 0) {
	  proto_tree_add_boolean_format(uru_tree, hf_uru_incomplete_dissection,
					rtvb, offset+12, 4, 1,
					"Unknown data in Ack (%08X)", zeros);
	}
	else {
	  /* we could add this to the tree, but we'd always hide it because we
	     hide the other ack parts (frn, sn, frnf, snf), so why bother? */
	}
	if (global_uru_header_style) {
	  proto_tree_add_none_format(uru_tree, hf_uru_ack, rtvb, offset,
				     16, "Ack %u,%u %u,%u",
				     sn, frn, snf, frnf);
	}
	else {
	  proto_tree_add_none_format(uru_tree, hf_uru_ack, rtvb, offset,
				     16, "%u(%u) < Ack <= %u(%u)",
				     snf, frnf, sn, frn);
	}
	offset += 16;
      }
    }
  }
  else if (flags == 0x00 || flags == UNetAckReq) {
    /* a plNetMessage */
    if (fragct == 0 || reassembled) {
      enum protocol_version v;

      netmsgtype = tvb_get_letohs(rtvb, offset);
      if (netmsgtype == NetMsgActivePlayerSet
	  && curr_conv->sport != curr_conv->cport
	  && curr_conv->sport == pinfo->srcport) {
	/* server->client NetMsgActivePlayerSet */
	v = UU;
      }
      else if (netmsgtype == NetMsgSetTimeout2
	       && curr_conv->sport != curr_conv->cport
	       && curr_conv->cport == pinfo->srcport) {
	v = POTS;
      }
      else {
	v = UNKNOWN;
      }

      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo,
			COL_INFO, "  %s",
			val_to_str(netmsgtype, 
				   v == UNKNOWN ? plNetMsgs
				     : v == UU ? uu_typecodes : pots_typecodes,
				   "Unknown (0x%04x)"));
      }
      if (tree) {
	if (v == UU) {
	  /* server->client NetMsgActivePlayerSet */
	  proto_tree_add_item(uru_tree, hf_uru_cmd_uu, rtvb, offset,
			      2, TRUE);
	  proto_item_append_text(ti, ", NetMessage: %s",
				 val_to_str(netmsgtype,  uu_typecodes,
					    "Unknown (0x%04x)"));
	}
	else if (v == POTS) {
	  /* client->server NetMsgSetTimeout */
	  proto_tree_add_item(uru_tree, hf_uru_cmd_pots, rtvb, offset,
			      2, TRUE);
	  proto_item_append_text(ti, ", NetMessage: %s",
				 val_to_str(netmsgtype,  pots_typecodes,
					    "Unknown (0x%04x)"));
	}
	else {
	  proto_tree_add_item(uru_tree, hf_uru_cmd, rtvb, offset, 2, TRUE);
	  proto_item_append_text(ti, ", NetMessage: %s",
				 val_to_str(netmsgtype,  plNetMsgs,
					    "Unknown (0x%04x)"));
	}
	offset += 2;

	offset = dissect_netmsg_flags(rtvb, offset, uru_tree);
	if (fragct != 0 && !reassembled) {
	  proto_item_append_text(ti, " fragment");
	  proto_tree_add_none_format(uru_tree, hf_uru_isfrag, rtvb, offset,
				     -1, "Fragment %u of %u", fragnum, fragct);
	}
	else if (tvb_length_remaining(rtvb, offset) > 0) {
	  gint parsed;

	  tf = proto_tree_add_item(uru_tree, hf_uru_msgbody, rtvb, offset,
				   -1, TRUE);
	  sub_tree = proto_item_add_subtree(tf, ett_netmsg);
	  parsed = dissect_plNetMessage(netmsgtype, rtvb, offset,
					sub_tree, pinfo);
	  if (!parsed || tvb_length_remaining(rtvb, parsed) > 0) {
	    tvbuff_t *ftvb;
	    gint bufsize, i, off;
	    guint8 *newbuf;

	    off = offset;
	    tf = proto_tree_add_boolean(tree, hf_uru_incomplete_dissection,
					rtvb, off, 0, 1);
	    PROTO_ITEM_SET_HIDDEN(tf);

	    /* TODO: maybe do this differently? dunno */
	    if (parsed) {
	      off = parsed;
	    }
	    bufsize = tvb_length_remaining(rtvb, off);
	    newbuf = tvb_memdup(rtvb, off, bufsize);
	    for (i = 0; i < bufsize; i++) {
	      newbuf[i] = ~newbuf[i];
	    }
	    ftvb = tvb_new_real_data(newbuf, bufsize, bufsize);
	    tvb_set_child_real_data_tvbuff(rtvb, ftvb);
	    tvb_set_free_cb(ftvb, g_free);
	    if (!parsed) {
	      add_new_data_source(pinfo, ftvb, "Bit-flipped Message Body");
	    }
	    else {
	      add_new_data_source(pinfo, ftvb, "Bit-flipped Data");
	      tf = proto_tree_add_text(uru_tree, rtvb, parsed, -1,
				       "UNKNOWN DATA");
	    }
	  }
	}
      }
    }
    else {
      if (tree) {
	proto_item_append_text(ti, ", NetMessage fragment");
	proto_tree_add_none_format(uru_tree, hf_uru_isfrag, rtvb, offset,
				   -1, "Fragment %u of %u", fragnum, fragct);
      }
    }
  }
  else {
    if (tree) {
      proto_tree_add_boolean_format(uru_tree, hf_uru_incomplete_dissection,
				    rtvb, offset,
				    tvb_length_remaining(rtvb, offset), 1,
				    "data (%d bytes)",
				    tvb_length_remaining(rtvb, offset));
      proto_item_append_text(ti, ", Unrecognized message type");
    }
    return;
  }
}

/* returns new offset */
static gint
dissect_netmsg_flags(tvbuff_t *rtvb, gint offset, proto_tree *uru_tree)
{
  proto_item *tf;
  proto_tree *sub_tree;
  guint32 netmsgflags;
  char *c;

  netmsgflags = tvb_get_letohl(rtvb, offset);
  c = ": ";
  tf = proto_tree_add_item(uru_tree, hf_uru_flags, rtvb, offset, 4, TRUE);
  sub_tree = proto_item_add_subtree(tf, ett_netmsgflags);
  proto_tree_add_item(sub_tree, hf_uru_flags_ts, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_notify, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plFlagsMaybeNotify) {
    proto_item_append_text(tf, "%sNotify?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_ip, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_firewalled, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetFirewalled) {
    proto_item_append_text(tf, "%sFirewalled", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_X, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_bcast, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetBcast) {
    proto_item_append_text(tf, "%sBroadcast", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_statereq, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetStateReq) {
    proto_item_append_text(tf, "%sStateReq?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_ki, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_avstate, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plFlagsMaybeAvatarState) {
    proto_item_append_text(tf, "%sAvState?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_guid, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_directed, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetDirected) {
    proto_item_append_text(tf, "%sDirected?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_version, rtvb, offset,
		      4, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_flags_custom, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetCustom) {
    proto_item_append_text(tf, "%sCustom?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_ack, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetAck) {
    proto_item_append_text(tf, "%sAck", c);
    c = "|";
  }
  if (netmsgflags & plNetSid) {
    /* custom flag (see unet3+) */
    proto_tree_add_item(sub_tree, hf_uru_flags_sid, rtvb, offset,
			4, TRUE);
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_p2p, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plNetP2P) {
    proto_item_append_text(tf, "%sP2P?", c);
    c = "|";
  }
  proto_tree_add_item(sub_tree, hf_uru_flags_unk, rtvb, offset,
		      4, TRUE);
  if (netmsgflags & plFlagsUnknown) {
    proto_item_append_text(tf, "%sUnknown", c);
    tf = proto_tree_add_boolean(uru_tree, hf_uru_incomplete_dissection,
				rtvb, offset, 4, 1);
    PROTO_ITEM_SET_HIDDEN(tf);
  }

  offset += 4;
  if (netmsgflags & plNetVersion) {
    guint8 max, min;
    max = tvb_get_guint8(rtvb, offset);
    min = tvb_get_guint8(rtvb, offset+1);
    if (!islive) {
      switch (min) {
      case 6:
	curr_conv->version = POTS;
	break;
      case 7:
	curr_conv->version = UU;
	break;
      }
    }
    proto_tree_add_none_format(uru_tree, hf_uru_version, rtvb, offset,
			       2, "Max version: %u, Min version: %u",
			       max, min);
    /* for packet filters */
    tf = proto_tree_add_item(uru_tree, hf_uru_maxversion, rtvb,
			     offset, 1, TRUE);
    PROTO_ITEM_SET_HIDDEN(tf);
    tf = proto_tree_add_item(uru_tree, hf_uru_minversion, rtvb,
			     offset+1, 1, TRUE);
    PROTO_ITEM_SET_HIDDEN(tf);
    offset += 2;
  }
  if (netmsgflags & plNetTimestamp) {
    add_uru_timestamp(rtvb, offset, uru_tree,
		      hf_uru_ts, hf_uru_ts_sec, hf_uru_ts_usec);
    offset += 8;
  }
  if (netmsgflags & plNetX) {
    proto_tree_add_item(uru_tree, hf_uru_X, rtvb, offset, 4, TRUE);
    offset += 4;
  }
  if (netmsgflags & plNetKi) {
    proto_tree_add_item(uru_tree, hf_uru_KI, rtvb, offset, 4, TRUE);
    offset += 4;
  }
  if (netmsgflags & plNetGUI) {
    tf = proto_tree_add_item(uru_tree, hf_uru_GUID, rtvb, offset,
			     16, FALSE);
    append_uru_uuid(tf, rtvb, offset);
    offset += 16;
  }
  if (netmsgflags & plNetIP) {
    /* The IP address is in network byte order, but the port isn't.
       Go figure! */
    proto_tree_add_item(uru_tree, hf_uru_IPaddr, rtvb, offset, 4, FALSE);
    proto_tree_add_item(uru_tree, hf_uru_port, rtvb, offset+4, 2, TRUE);
    offset += 6;
  }
  /* custom flag (see unet3+) */
  if (netmsgflags & plNetSid) {
    proto_tree_add_item(uru_tree, hf_uru_sid, rtvb, offset, 4, TRUE);
    offset += 4;
  }
  return offset;
}

/* returns new offset, or 0 if not recognized */
static gint
dissect_plNetMessage(guint16 type,
		     tvbuff_t *tvb,
		     gint offset,
		     proto_tree *tree,
		     packet_info *pinfo)
{
  proto_item *tf;
  tvbuff_t *ntvb;
  char *str;
  guint slen;
  gint noffset, treect = 0;

  SBRK(tree, tvb, offset);
  if (type == NetMsgJoinReq
      || type == NetMsgRequestMyVaultPlayerList
      || type == NetMsgActivePlayerSet2
      || type == NetMsgMembersListReq
      || type == NetMsgAlive) {
    /* no body - dissect_plNetMessage need not be called for these, but
       if there is extra data, this way it will be marked as such */
    return offset;
  }
  else if (type == NetMsgActivePlayerSet
	   && ((!islive && curr_conv->version == UU) || islive)) {
    /* no body */
    return offset;
  }
  else if (type == NetMsgJoinAck || type == NetMsgSDLState
	   || type == NetMsgSDLStateBCast) {
    guint16 flag16;
    guint8 cflag;
    guint32 unclen, sdllen;
    gint bufend;

    if (type == NetMsgJoinAck) {
      flag16 = tvb_get_letohs(tvb, offset);
      tf = proto_tree_add_item(tree, hf_uru_join_unkflag, tvb, offset,
			       2, TRUE);
      if (global_uru_hide_stuff && flag16 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      offset += 2;
    }
    else if (type == NetMsgSDLState || type == NetMsgSDLStateBCast) {
      offset = dissect_uru_object_subtree(tvb, offset, tree,
					  ETT_ODESC(treect), NULL,
					  FALSE, NULL, NULL, NULL,
					  -1, 0, hf_uru_obj);
      treect++;
    }
    unclen = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_sdl_uncsize, tvb, offset, 4, TRUE);
    offset += 4;
    cflag = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_uru_sdl_cflag, tvb, offset, 1, TRUE);
    offset += 1;
    sdllen = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_sdl_sdllen, tvb, offset, 4, TRUE);
    offset += 4;
    if (sdllen == 0) {
      /* we're done XXX endthing? */
      return offset;
    }
    if ((int)sdllen > tvb_length_remaining(tvb, offset)) {
      tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					 tvb, offset-4, 4, 1,
					 "SDL length too long");
      PROTO_ITEM_SET_GENERATED(tf);
      sdllen = tvb_length_remaining(tvb, offset);
    }
    flag16 = tvb_get_letohs(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_gamemsg_type, tvb, offset, 2, TRUE);
    if (global_uru_hide_stuff && flag16 == 0x8000) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 2;
    if (cflag == kCompressionZlib) {
#ifdef HAVE_LIBZ
      ntvb = tvb_uncompress(tvb, offset, sdllen-2);
#else
      ntvb = NULL;
#endif
      if (!ntvb) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					   tvb, offset, sdllen-2, 1,
					   "Uncompress failed!");
	PROTO_ITEM_SET_GENERATED(tf);
	SBRK(tree, tvb, offset);
	return offset;
      }
      tvb_set_child_real_data_tvbuff(tvb, ntvb);
      add_new_data_source(pinfo, ntvb, "Uncompressed data");
      tvb_set_free_cb(ntvb, g_free);
      noffset = 0;
      if (tvb_length_remaining(ntvb, 0) != (gint)unclen-2) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
			    tvb, offset, tvb_length_remaining(ntvb, 0), 1,
			    "Uncompressed length doesn't match, actual: %u",
			    tvb_length_remaining(ntvb, 0));
	PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    else {
      ntvb = tvb;
      noffset = offset;
    }
    bufend = tvb_length_remaining(ntvb, noffset)+noffset;
    if (cflag != kCompressionZlib) {
      /* these bytes are all after the compressed part, so if it was
	 compressed, they are not present in ntvb and do not need to be
	 avoided */
      if (type != NetMsgJoinAck) {
	bufend--; /* for endthing */
      }
      if (islive) {
	bufend -= 2;
      }
      else if (type == NetMsgSDLStateBCast) {
	bufend--;
      }
    }

    noffset = dissect_sdl_msg(ntvb, noffset, tree, bufend);

    if (cflag == kCompressionZlib) {
      if (tvb_length_remaining(ntvb, noffset) > 0) {
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, noffset, 
				      tvb_length_remaining(ntvb, noffset),
				      1, "UNKNOWN DATA");
      }
      offset += sdllen-2;
    }
    else {
      if (noffset < bufend) {
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, noffset, bufend-noffset,
				      1, "UNKNOWN DATA");
      }
      offset = bufend;
    }
    /* XXX I suspect both end things here are "initial age state":
       like hf_uru_loadclone_init */
    if (islive) {
      /* XXX this is the submessage "end thing" + 1 byte */
      proto_tree_add_item(tree, hf_uru_sdl_unk02, tvb, offset, 2, TRUE);
      offset += 2;
    }
    else if (type == NetMsgSDLStateBCast) {
      /* XXX this is the submessage "end thing" */
      proto_tree_add_item(tree, hf_uru_sdl_unk01, tvb, offset, 1, TRUE);
      offset += 1;
    }
    if (type != NetMsgJoinAck) {
      proto_tree_add_item(tree, hf_uru_sdl_endthing, tvb, offset, 1, TRUE);
      offset += 1;
    }
    return offset;
  }
  else if (type == NetMsgLeave) {
    proto_tree_add_item(tree, hf_uru_leave_reason, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgTerminated) {
    proto_tree_add_item(tree, hf_uru_term_reason, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgPing) {
    proto_tree_add_item(tree, hf_uru_ping_mtime, tvb, offset, 8, TRUE);
    offset += 8;
    proto_tree_add_item(tree, hf_uru_ping_dest, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgAuthenticateHello) {
    if (!islive && curr_conv->sport == 0) {
      /* these should be set *outside* of an "if (tree)" block */
      curr_conv->sport = pinfo->destport;
      curr_conv->cport = pinfo->srcport;
    }
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_auth_login, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    proto_tree_add_item(tree, hf_uru_auth_maxpacket, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(tree, hf_uru_auth_release, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgAuthenticateChallenge) {
    if (!islive && curr_conv->sport == 0) {
      /* these should be set *outside* of an "if (tree)" block */
      curr_conv->sport = pinfo->srcport;
      curr_conv->cport = pinfo->destport;
    }
    proto_tree_add_item(tree, hf_uru_auth_resp, tvb, offset, 1, TRUE);
    offset += 1;
    str = get_uru_hexstring(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_auth_hash, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    return offset;
  }
  else if (type == NetMsgAuthenticateResponse) {
    str = get_uru_hexstring(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_auth_hash, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    return offset;
  }
  else if (type == NetMsgAccountAuthenticated) {
    proto_tree_add_item(tree, hf_uru_auth_resp, tvb, offset, 1, TRUE);
    offset += 1;
    proto_tree_add_item(tree, hf_uru_auth_sguid, tvb, offset, 8, FALSE);
    offset += 8;
    return offset;
  }
  else if (type == NetMsgVaultPlayerList) {
    guint16 playerct, i;

    playerct = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_uru_plist_ct, tvb, offset, 2, TRUE);
    offset += 2;
    for (i = 0; i < playerct; i++) {
      str = get_uru_string(tvb, offset+4, &slen);
      proto_tree_add_item(tree, hf_uru_plist, tvb, offset, slen+5, TRUE);
      proto_tree_add_item(tree, hf_uru_plist_ki, tvb, offset, 4, TRUE);
      offset += 4;
      proto_tree_add_STR(tree, hf_uru_plist_name, tvb, offset, slen, str);
      MAYBE_FREE(str);
      offset += slen;
      proto_tree_add_item(tree, hf_uru_plist_flags, tvb, offset, 1, TRUE);
      offset += 1;
    }
    if (tvb_length_remaining(tvb, offset) > 0) {
      str = get_uru_string(tvb, offset, &slen);
      proto_tree_add_STR(tree, hf_uru_plist_url, tvb, offset, slen, str);
      MAYBE_FREE(str);
      offset += slen;
    }
    return offset;
  }
  else if (type == NetMsgSetMyActivePlayer) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_setact_name, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    proto_tree_add_item(tree, hf_uru_setact_code, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgFindAge) {
    return dissect_age_link(tvb, offset, tree, TRUE);
  }
  else if (type == NetMsgFindAgeReply) {
    guint8 flag;

    flag = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_findrply_unk1f, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && flag == 0x1f) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_findrply_name, tvb, offset, slen,
		       str);
    MAYBE_FREE(str);
    offset += slen;
    proto_tree_add_item(tree, hf_uru_findrply_srvtype, tvb, offset, 1, TRUE);
    offset += 1;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_findrply_server, tvb, offset, slen,
		       str);
    MAYBE_FREE(str);
    offset += slen;
    proto_tree_add_item(tree, hf_uru_findrply_port, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(tree, hf_uru_findrply_guid, tvb, offset, 8, FALSE);
    offset += 8;
    return offset;
  }
  else if (type == NetMsgPagingRoom) {
    guint32 format;

    format = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_pageroom_format, tvb, offset, 4, TRUE);
    offset += 4;
    if (format == 0x01) {
      proto_tree_add_item(tree, hf_uru_pageroom_pageid, tvb, offset, 4, TRUE);
      offset += 4;
      proto_tree_add_item(tree, hf_uru_pageroom_pagetype, tvb, offset, 2,
			  TRUE);
      offset += 2;
      str = get_uru_string(tvb, offset, &slen);
      proto_tree_add_STR(tree, hf_uru_pageroom_pagename, tvb, offset,
			 slen, str);
      MAYBE_FREE(str);
      offset += slen;
    }
    proto_tree_add_item(tree, hf_uru_pageroom_page, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgGroupOwner) {
    guint8 unk;

    proto_tree_add_item(tree, hf_uru_groupown_mask, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_uru_groupown_pageid, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_uru_groupown_pagetype, tvb, offset, 2, TRUE);
    offset += 2;
    unk = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_groupown_unk0, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && unk == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    proto_tree_add_item(tree, hf_uru_groupown_flags, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgLoadClone) {
    guint32 unk32;
    gint32 sublen;
    guint8 unk8;
    guint16 unk16, subtype, objtype;

    /* parse_adv_msg() */
    unk32 = tvb_get_letohl(tvb, offset);
    /* XXX this is "uncompressed size" */
    tf = proto_tree_add_item(tree, hf_uru_loadclone_unk1, tvb, offset,
			     4, TRUE);
    if (global_uru_hide_stuff && unk32 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    unk8 = tvb_get_guint8(tvb, offset);
    /* XXX this is "compression flag" */
    tf = proto_tree_add_item(tree, hf_uru_loadclone_unk2, tvb, offset,
			     1, TRUE);
    if (global_uru_hide_stuff && unk8 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    sublen = tvb_get_letohl(tvb, offset);
    /* XXX this is "message length" */
    proto_tree_add_item(tree, hf_uru_loadclone_sublen, tvb, offset, 4, TRUE);
    offset += 4;
    /* parse_sub_msg() */
    noffset = offset;
    subtype = tvb_get_letohs(tvb, noffset);
    if (!islive) {
      proto_tree_add_item(tree, hf_uru_loadclone_subtype, tvb, noffset,
			  2, TRUE);
    }
    else {
      proto_tree_add_item(tree, hf_urulive_loadclone_subtype, tvb, noffset,
			  2, TRUE);
      subtype = live_translate(subtype);
    }
    noffset += 2;
    if (subtype == plLoadAvatarMsg || subtype == plLoadCloneMsg) {
      /* XXX run this through dissect_plNetMsg again! */
      unk8 = tvb_get_guint8(tvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk0, tvb, noffset,
			       1, TRUE);
      if (global_uru_hide_stuff && unk8 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 1;
      unk32 = tvb_get_letohl(tvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk1, tvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 1) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      noffset = dissect_uru_object_subtree(tvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, &objtype, NULL,
					   hf_uru_loadclone_netmgrexists,
					   1, hf_uru_loadclone_netmgr);
      treect++;
      if (objtype != plNetClientMgr) {
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      tvb, noffset, offset+sublen-noffset, 1,
				      "Unrecognized manager");
	offset = sublen;
      }
      else {
	unk32 = tvb_get_letohl(tvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk4, tvb, noffset,
				 4, TRUE);
	if (global_uru_hide_stuff && unk32 == 0) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 4;
	unk32 = tvb_get_letohl(tvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk5, tvb, noffset,
				 4, TRUE);
	if (global_uru_hide_stuff && unk32 == 0) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 4;
	unk32 = tvb_get_letohl(tvb, noffset);
	proto_tree_add_item(tree, hf_uru_loadclone_subunk6, tvb, noffset,
			    4, TRUE);
	noffset += 4;
	noffset = dissect_uru_object_subtree(tvb, noffset, tree,
					     ETT_ODESC(treect), NULL,
					     TRUE, NULL, NULL, NULL,
					     hf_uru_subobj_exists,
					     1, hf_uru_subobj);
	treect++;
	noffset = dissect_uru_object_subtree(tvb, noffset, tree,
					     ETT_ODESC(treect), NULL,
					     TRUE, NULL, &objtype, NULL,
					     hf_uru_loadclone_avmgrexists,
					     1, hf_uru_loadclone_avmgr);
	treect++;
	if (objtype != plAvatarMgr) {
	  proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
					tvb, noffset, offset+sublen-noffset, 1,
					"Unrecognized type");
	  offset = sublen;
	}
	else {
	  proto_tree_add_item(tree, hf_uru_loadclone_id, tvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  unk32 = tvb_get_letohl(tvb, noffset);
	  proto_tree_add_item(tree, hf_uru_loadclone_parentid, tvb,
			      noffset, 4, TRUE);
	  noffset += 4;
	  unk8 = tvb_get_guint8(tvb, noffset);
	  tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk11, tvb,
				   noffset, 1, TRUE);
	  if (global_uru_hide_stuff && unk8 == 1) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_loadclone_subpage, tvb,
			      noffset, 1, TRUE);
	  noffset += 1;
	  unk16 = tvb_get_letohs(tvb, noffset);
	  if (!islive) {
	    proto_tree_add_item(tree, hf_uru_loadclone_subctype, tvb,
				noffset, 2, TRUE);
	  }
	  else {
	    proto_tree_add_item(tree, hf_urulive_loadclone_subctype, tvb,
				noffset, 2, TRUE);
	    unk16 = live_translate(unk16);
	  }
	  noffset += 2;
	  if (subtype == 0x8000) {
	    /* done */
	  }
	  else if (subtype == plLoadCloneMsg) {
	    /* not in parse_sub_msg() */
	    if (unk16 == plParticleTransferMsg) {
	      /* hmm, it repeats, basically */
	      /* XXX no! It is exactly a plParticleTransferMsg, see below */
	      unk8 = tvb_get_guint8(tvb, noffset);
	      tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk0, tvb,
				  noffset, 1, TRUE);
	      if (global_uru_hide_stuff && unk8 == 0) {
		PROTO_ITEM_SET_HIDDEN(tf);
	      }
	      noffset += 1;
	      unk32 = tvb_get_letohl(tvb, noffset);
	      proto_tree_add_item(tree, hf_uru_loadclone_subunk1, tvb,
				  noffset, 4, TRUE);
	      noffset += 4;
	      noffset = dissect_uru_object_subtree(tvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, &objtype, NULL,
					   hf_uru_loadclone_netmgrexists,
					   1, hf_uru_loadclone_netmgr);
	      treect++;
	      unk32 = tvb_get_letohl(tvb, noffset);
	      tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk4, tvb,
				       noffset, 4, TRUE);
	      if (global_uru_hide_stuff && unk32 == 0) {
		PROTO_ITEM_SET_HIDDEN(tf);
	      }
	      noffset += 4;
	      unk32 = tvb_get_letohl(tvb, noffset);
	      tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk5, tvb,
				       noffset, 4, TRUE);
	      noffset += 4;
	      if (global_uru_hide_stuff && unk32 == 0) {
		PROTO_ITEM_SET_HIDDEN(tf);
	      }
	      unk32 = tvb_get_letohl(tvb, noffset);
	      proto_tree_add_item(tree, hf_uru_loadclone_subunk6, tvb,
				  noffset, 4, TRUE);
	      noffset += 4;
	      noffset = dissect_uru_object_subtree(tvb, noffset, tree,
						   ETT_ODESC(treect), NULL,
						   TRUE, NULL, &subtype, NULL,
						   hf_uru_loadclone_subexists,
						   1, hf_uru_loadclone_subobj);
	      treect++;
	      /* this makes sense... */
	      proto_tree_add_item(tree, hf_uru_particle_count, tvb,
				  noffset, 2, TRUE);
	      noffset += 2;
	    }
	    else {
	      /* XXX */
	    }
	  }
	  else if (subtype == plLoadAvatarMsg) {
	    proto_tree_add_item(tree, hf_uru_loadclone_subunk13, tvb,
				noffset, 1, TRUE);
	    noffset += 1;
	    noffset = dissect_uru_object_subtree(tvb, noffset, tree,
						 ETT_ODESC(treect), NULL,
						 TRUE, NULL, &subtype, NULL,
						 hf_uru_loadclone_subexists,
						 1, hf_uru_loadclone_subobj);
	    treect++;
	    unk8 = tvb_get_guint8(tvb, noffset);
	    tf = proto_tree_add_item(tree, hf_uru_loadclone_subunk13a, tvb,
				     noffset, 1, TRUE);
	    noffset += 1;
	    if (islive && (live_conv->isv1 < 0 || offset+sublen > noffset)) {
	      str = get_uru_string(tvb, noffset, &slen);
	      proto_tree_add_STR(tree, hf_urulive_loadclone_name, tvb,
				 noffset, slen, str);
	      noffset += slen;
	    }
	  }
	}
	if (offset+sublen != noffset) {
	  if (offset+sublen > noffset) {
	    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					  tvb, noffset,
					  offset+sublen-noffset, 1,
					  "Lengths don't match, actual: %u",
					  noffset-offset);
	  }
	  else {
	    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					  tvb, offset+sublen,
					  noffset-(offset+sublen), 1,
					  "Lengths don't match, actual: %u",
					  noffset-offset);
	  }
	  PROTO_ITEM_SET_GENERATED(tf);
	}
	offset += sublen;
      }
    }
    else {
      proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				    tvb, noffset, sublen, 1,
				    "Unrecognized sub message");
      offset += sublen;
    }
    /* back to parse_adv_msg() */
    unk8 = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_loadclone_unk3, tvb, offset,
			     1, TRUE);
    if (global_uru_hide_stuff && unk8 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    offset = dissect_uru_object_subtree(tvb, offset, tree,
					ETT_ODESC(treect), NULL,
					FALSE, NULL, NULL, NULL,
					-1, 0, hf_uru_obj);
    treect++;
    unk8 = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_loadclone_unk4, tvb, offset,
			     1, TRUE);
    if (global_uru_hide_stuff && unk8 == 1) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    proto_tree_add_item(tree, hf_uru_loadclone_page, tvb, offset, 1, TRUE);
    offset += 1;
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_item(tree, hf_uru_loadclone_init, tvb, offset,
			  1, TRUE);
      offset += 1;
    }
    return offset;
  }
  else if (type == NetMsgPlayerPage) {
    proto_tree_add_item(tree, hf_uru_ppage_page, tvb, offset, 1, TRUE);
    offset += 1;
    offset = dissect_uru_object_subtree(tvb, offset, tree,
					ett_odesc, NULL,
					FALSE, NULL, NULL, NULL,
					-1, 0, hf_uru_obj);
    return offset;
  }
  else if (type == NetMsgGameStateRequest) {
    guint32 reqct, i;

    reqct = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_gsreq_ct, tvb, offset, 4, TRUE);
    offset += 4;
    for (i = 0; i < reqct; i++) {
      proto_tree_add_item(tree, hf_uru_gsreq_pageid, tvb, offset, 4, TRUE);
      offset += 4;
      proto_tree_add_item(tree, hf_uru_gsreq_pagetype, tvb, offset, 2, TRUE);
      offset += 2;
      str = get_uru_string(tvb, offset, &slen);
      proto_tree_add_STR(tree, hf_uru_gsreq_name, tvb, offset, slen, str);
      MAYBE_FREE(str);
      offset += slen;
    }
    return offset;
  }
  else if (type == NetMsgInitialAgeStateSent) {
    proto_tree_add_item(tree, hf_uru_stsent_num, tvb, offset, 4, TRUE);
    offset += 4;
    return offset;
  }
  else if (type == NetMsgMemberUpdate || type == NetMsgMembersList) {
    guint8 memberct;
    guint32 ki, ipaddr, unk32;
    guint16 contents, port, unk16;
    guint8 unk8;
    gint off, off2;
    guint i;
    proto_item *ti = NULL/*shut up compiler*/;
    proto_tree *ltree;

    if (type == NetMsgMembersList) {
      memberct = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_uru_mlist_ct, tvb, offset, 2, TRUE);
      offset += 2;
    }
    else {
      memberct = 1;
    }
    for (i = 0; i < memberct; i++) {
      if (type == NetMsgMembersList) {
	ti = proto_tree_add_none_format(tree, hf_uru_mlist_player, tvb, offset,
					0, "Player:");
	ltree = proto_item_add_subtree(ti, ett_members);
      }
      else {
	ltree = tree;
      }
      off = offset;
      unk32 = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(ltree, hf_uru_mlist_unkflags, tvb, offset, 4, TRUE);
      offset += 4;
      contents = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(ltree, hf_uru_mlist_cts, tvb, offset, 2, TRUE);
      offset += 2;
      if (contents & kPlayerID/*0x0002*/) {
	ki = tvb_get_letohl(tvb, offset);
	tf = proto_tree_add_item(ltree, hf_uru_mlist_ki, tvb, offset, 4, TRUE);
	if (type == NetMsgMembersList) {
	  proto_item_append_text(ti, " KI: %u", ki);
	  if (global_uru_hide_stuff) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	}
	offset += 4;
      }
      if (contents & kPlayerName/*0x0040*/) {
	str = get_uru_string(tvb, offset, &slen);
	tf = proto_tree_add_STR(ltree, hf_uru_mlist_name, tvb, offset,
				slen, str);
	if (type == NetMsgMembersList) {
	  proto_item_append_text(ti, " Name: %s", str);
	  if (global_uru_hide_stuff) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	}
	MAYBE_FREE(str);
	offset += slen;
      }
      if (contents & kBuildType/*0x0020*/) {
	unk16 = tvb_get_letohs(tvb, offset);
	tf = proto_tree_add_item(ltree, hf_uru_mlist_buildtype, tvb, offset,
				 2, TRUE);
	if (global_uru_hide_stuff && unk16 == 0x0300) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	offset += 2;
      }
      if (contents & kSrcAddr/*0x0080*/) {
#if 0
	/* I can't use tvb_get_ipv4 because the IP address is not transmitted
	   in network order! */
	ipaddr = tvb_get_letohl(tvb, offset);
	tf = proto_tree_add_item(ltree, hf_uru_mlist_ip, tvb, offset, 4, TRUE);
	if (type == NetMsgMembersList) {
	  proto_item_append_text(ti, " IP Address: %u.%u.%u.%u",
				 ipaddr>>24, (ipaddr>>16)&0xFF,
				 (ipaddr>>8)&0xFF, ipaddr&0xFF);
	  if (global_uru_hide_stuff) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	}
#else
	(void)ipaddr; /* shut up compiler */
#endif
	offset += 4;
      }
      if (contents & kSrcPort/*0x0100*/) {
	port = tvb_get_letohs(tvb, offset);
	tf = proto_tree_add_item(ltree, hf_uru_mlist_port, tvb, offset,
				 2, TRUE);
	if (type == NetMsgMembersList) {
	  proto_item_append_text(ti, " Port: %u", port);
	  if (global_uru_hide_stuff) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	}
	offset += 2;
      }
      if (contents & kCCRLevel/*0x0008*/) {
	unk8 = tvb_get_guint8(tvb, offset);
	tf = proto_tree_add_item(ltree, hf_uru_mlist_vis, tvb, offset, 1, TRUE);
	if (global_uru_hide_stuff && unk8 == 0) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	else if (unk8 & 0x04) {
	  /* ResEng hidden flag -- see PlayerInfoNode Int32_2 */
	  proto_item_append_text(tf, " (Mostly Hidden)");
	}
	offset += 1;
      }
      if (1) { /* always present? -- but expect 0x0200 or kClientKey */
	off2 = offset;
	offset = dissect_uru_object_subtree(tvb, offset, ltree,
					    -1, &str,
					    FALSE, NULL, NULL, NULL,
					    -1, 1, -1);
	proto_tree_add_STR(ltree, hf_uru_mlist_key, tvb, off2, offset-off2,
			   str);
	MAYBE_FREE(str);
      }
      if (type == NetMsgMembersList) {
	proto_item_set_len(ti, offset-off);
      }
    }
    if (type == NetMsgMemberUpdate) {
      proto_tree_add_item(tree, hf_uru_mlist_page, tvb, offset, 1, TRUE);
      offset += 1;
    }
    return offset;
  }
  else if (type == NetMsgSetTimeout || type == NetMsgSetTimeout2) {
    if (type == NetMsgSetTimeout2) {
      /* perhaps it is actually NetMsgActivePlayerSet */
      if (tvb_length_remaining(tvb, offset) < 4) {
	/* let's assume so */
	return offset;
      }
    }
    proto_tree_add_item(tree, hf_uru_timeout, tvb, offset, 4, TRUE);
    offset += 4;
    return offset;
  }
  else if (type == NetMsgTestAndSet) {
    guint32 unk32;
    gint32 msglen;
    gint msgstart;
    gint8 unk8;

    if (!islive && curr_conv->sport == 0) {
      /* these should be set *outside* of an "if (tree)" block */
      curr_conv->sport = pinfo->destport;
      curr_conv->cport = pinfo->srcport;
    }
    offset = dissect_uru_object_subtree(tvb, offset, tree,
					ETT_ODESC(treect), NULL,
					FALSE, NULL, NULL, NULL,
					-1, 0, hf_uru_obj);
    treect++;
    unk8 = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_test_flag1, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && unk8 == 0x00) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_test_unk1, tvb, offset, 4, TRUE);
    if (global_uru_hide_stuff && unk32 == 0x00) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    msglen = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_test_msglen, tvb, offset, 4, TRUE);
    offset += 4;
    msgstart = offset;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_test_type, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_test_unk3, tvb, offset, 4, TRUE);
    if (global_uru_hide_stuff && unk32 == 0x00) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    proto_tree_add_item(tree, hf_uru_test_state1, tvb, offset, 1, TRUE);
    offset += 1;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_test_state, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    unk8 = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_test_flag2, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && unk8 == 0x02) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    proto_tree_add_item(tree, hf_uru_test_state2, tvb, offset, 1, TRUE);
    offset += 1;
    if (offset != msgstart+msglen) {
      if (offset > msgstart+msglen) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
				      tvb, msgstart+msglen,
				      offset-(msgstart+msglen), 1,
				      "Lengths don't match, actual: %u",
				      offset-msgstart);
      }
      else {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
				      tvb, offset,
				      msgstart+msglen-offset, 1,
				      "Lengths don't match, actual: %u",
				      offset-msgstart);
      }
      PROTO_ITEM_SET_GENERATED(tf);
    }
    proto_tree_add_item(tree, hf_uru_test_endthing, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgVoice) {
    guint16 msglen = 0;
    guint8 recipct, i;
    guint32 kinum;

    i = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_voice_unk0, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && i == 0x01) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    /* this next number might be the number of frames, something like that */
    proto_tree_add_item(tree, hf_uru_voice_unk1, tvb, offset, 1, TRUE);
    offset += 1;
    msglen = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_uru_voice_msglen, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(tree, hf_uru_voice_data, tvb, offset, msglen, TRUE);
    offset += msglen;
    /* start of recipients list */
    recipct = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_uru_voice_recipct, tvb, offset, 1, TRUE);
    offset += 1;
    if (tvb_length_remaining(tvb, offset) < (4*recipct)) {
      tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, tvb,
				    offset, tvb_length_remaining(tvb, offset),
				    1, "Not enough recipients");
      PROTO_ITEM_SET_GENERATED(tf);
      return offset;
    }
    for (i = 0; i < recipct; i++) {
      kinum = tvb_get_letohl(tvb, offset);
      proto_tree_add_uint_format(tree, hf_uru_voice_recip, tvb, offset,
				 4, kinum, "  %u", kinum);
      offset += 4;
    }
    return offset;
  }
  else if (type == NetMsgVault || type == NetMsgVault2
	   || type == NetMsgVaultTask) {
    /* info from plVaultUnpack */
    guint8 cflag;
    guint32 msglen = 0;
    gint32 unclen; 
    guint16 itemct, i, id, dtype;

    /* auto-detect protocol version */
    if (!islive && curr_conv->version == UNKNOWN
	&& curr_conv->sport != curr_conv->cport
	&& curr_conv->sport == pinfo->srcport) {
      if (type == NetMsgVault) {
	/* this should be set *outside* of an "if (tree)" block */
	curr_conv->version = UU;
      }
      else if (type == NetMsgVault2) {
	/* this should be set *outside* of an "if (tree)" block */
	curr_conv->version = POTS;
      }
    }

    tf = proto_tree_add_item(tree, hf_uru_vault_cmd, tvb, offset, 1, TRUE);
    if (type == NetMsgVaultTask) {
      PROTO_ITEM_SET_HIDDEN(tf); /* for filters */
      proto_tree_add_item(tree, hf_uru_vault_task, tvb, offset, 1, TRUE);
    }
    offset += 1;
    proto_tree_add_item(tree, hf_uru_vault_result, tvb, offset, 2, TRUE);
    offset += 2;
    cflag = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_uru_vault_cflag, tvb, offset, 1, TRUE);
    offset += 1;
    unclen = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_vault_uncsize, tvb, offset, 4, TRUE);
    offset += 4;
    if (cflag == 0x03) { /* just to be different :P */
      msglen = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(tree, hf_uru_vault_msglen, tvb, offset, 4, TRUE);
      offset += 4;
#ifdef HAVE_LIBZ
      ntvb = tvb_uncompress(tvb, offset, msglen);
#else
      ntvb = NULL;
#endif
      if (!ntvb) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					   tvb, offset,
					   tvb_length_remaining(tvb, offset),
					   1, "Uncompress failed!");
	PROTO_ITEM_SET_GENERATED(tf);
	return offset;
      }
      tvb_set_child_real_data_tvbuff(tvb, ntvb);
      add_new_data_source(pinfo, ntvb, "Uncompressed data");
      tvb_set_free_cb(ntvb, g_free);
      noffset = 0;
      if (tvb_length_remaining(ntvb, 0) != unclen) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
			    tvb, offset, msglen, 1,
			    "Uncompressed length doesn't match, actual: %u",
			    tvb_length_remaining(ntvb, 0));
	PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    else {
      ntvb = tvb;
      noffset = offset;
    }
    itemct = tvb_get_letohs(ntvb, noffset);
    proto_tree_add_item(tree, hf_uru_vault_itemct, ntvb, noffset, 2, TRUE);
    noffset += 2;
    for (i = 0; i < itemct; i++) {
      id = tvb_get_letohs(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_vault_id, ntvb, noffset, 2, TRUE);
      noffset += 2;
      dtype = tvb_get_letohs(ntvb, noffset);
      if (!islive && dtype == plVaultNode && curr_conv->version != UNKNOWN) {
	if (curr_conv->version == UU) {
	  proto_tree_add_item(tree, hf_uru_vault_dtype_uu, ntvb, noffset,
			      2, TRUE);
	}
	else {
	  proto_tree_add_item(tree, hf_uru_vault_dtype_pots, ntvb, noffset,
			      2, TRUE);
	}
      }
      else if (islive) {
	proto_tree_add_item(tree, hf_uru_vault_dtype_uu, ntvb, noffset,
			    2, TRUE);
      }
      else {
	proto_tree_add_item(tree, hf_uru_vault_dtype, ntvb, noffset,
			    2, TRUE);
      }
      noffset += 2;
      if (dtype == plCreatableGenericValue) {
	guint8 format;
	format = tvb_get_guint8(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_vault_cgv_format, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
	if (format == DInteger) {
	  proto_tree_add_item(tree, hf_uru_vault_cgv_int, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	}
	else if (format == DUruString) {
	  str = get_uru_string(ntvb, noffset, &slen);
	  proto_tree_add_STR(tree, hf_uru_vault_cgv_str, ntvb, noffset,
			     slen, str);
	  MAYBE_FREE(str);
	  noffset += slen;
	}
	else if (format == DTimestamp) {
	  guint32 t1, t2;
	  gdouble t;
	  t = tvb_get_letohieee_double(ntvb, noffset);
	  tf = proto_tree_add_item(tree, hf_uru_vault_cgv_ts, ntvb, noffset,
				   8, TRUE); /* a double according to Alcugs */
	  t1 = (guint32)t;
	  t2 = (guint32)((t-t1)*1000000);
	  append_ts_formatted(tf, t1, t2, TRUE);
	  noffset += 8;
	}
	else {
	  proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
					ntvb, noffset-1, 1, 1,
					"Can't dissect unknown format!");
	  return offset;
	}
      }
      else if (dtype == plCreatableStream) {
	guint32 streamlen;
	proto_item *len_tf;

	streamlen = tvb_get_letohl(ntvb, noffset);
	len_tf = proto_tree_add_item(tree, hf_uru_vault_cs_len, ntvb, noffset,
				     4, TRUE);
	noffset += 4;
	tf = proto_tree_add_item(tree, hf_uru_vault_cs_stream, ntvb, noffset,
				 streamlen, TRUE);
	if (global_uru_parse_vault_streams) {
	  /* TODO: other ids? */
	  if (id == 0x000e) { /* TODO: put in number->name mappings */
	    guint32 ct, j;
	    int soffset;
	    proto_tree *sub_tree;

	    soffset = noffset;
	    sub_tree = proto_item_add_subtree(tf, ett_vault_manifest);
	    ct = tvb_get_letohl(ntvb, soffset);
	    proto_tree_add_item(sub_tree, hf_uru_vault_nego_ct4, ntvb, soffset,
				4, TRUE);
	    proto_item_append_text(len_tf, " (%u node%s)", ct,
				   plurality(ct, "", "s"));
	    soffset += 4;
	    for (j = 0; j < ct; j++) {
	      guint32 idx, t1, t2;
	      gdouble t;
	      idx = tvb_get_letohl(ntvb, soffset);
	      t = tvb_get_letohieee_double(ntvb, soffset+4);
	      t1 = (guint32)t;
	      t2 = (guint32)((t-t1)*1000000);
	      tf = proto_tree_add_bytes_format(sub_tree,
		       hf_uru_vault_nego_node, ntvb, soffset, 12,
		       tvb_get_ptr(ntvb, soffset, 12),
		       global_uru_header_style
                         ? "  ID:%u Stamp:%d.%06d" : "  %u time: %d.%06d",
		       idx, t1, t2);
	      append_ts_formatted(tf, t1, t2, TRUE);
	      tf = proto_tree_add_item(sub_tree, hf_uru_node_trackid, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      soffset += 12;
	    }
	    /* TODO: verify soffset-noffset == streamlen */
	  }
	  else if (id == 0x000f) {
	    guint32 ct, j;
	    int soffset;
	    proto_tree *sub_tree;

	    soffset = noffset;
	    sub_tree = proto_item_add_subtree(tf, ett_vault_reflist);
	    ct = tvb_get_letohl(ntvb, soffset);
	    proto_tree_add_item(sub_tree, hf_uru_vault_nego_ct4, ntvb, soffset,
				4, TRUE);
	    proto_item_append_text(len_tf, " (%u reference%s)", ct,
				   plurality(ct, "", "s"));
	    soffset += 4;
	    for (j = 0; j < ct; j++) {
	      guint32 id1, id2, id3, t1, t2;
	      gchar f;
	      id1 = tvb_get_letohl(ntvb, soffset);
	      id2 = tvb_get_letohl(ntvb, soffset+4);
	      id3 = tvb_get_letohl(ntvb, soffset+8);
	      t1 = tvb_get_letohl(ntvb, soffset+12);
	      t2 = tvb_get_letohl(ntvb, soffset+16);
	      f = tvb_get_guint8(ntvb, soffset+20);
	      tf = proto_tree_add_bytes_format(sub_tree,
		       hf_uru_vault_nego_ref, ntvb, soffset, 21,
		       tvb_get_ptr(ntvb, soffset, 21),
		       global_uru_header_style
                         ? "  Id1:%u Id2:%u Id3:%u Flag:%u Stamp: %d.%06d"
                         : "  %u->%u (%u) flag: %u time: %d.%06d",
		       global_uru_header_style ? id1 : id2,
		       global_uru_header_style ? id2 : id3,
		       global_uru_header_style ? id3 : id1,
		       f, t1, t2);
	      append_ts_formatted(tf, t1, t2, FALSE);
	      tf = proto_tree_add_item(sub_tree, hf_uru_vault_ref_id1, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      tf = proto_tree_add_item(sub_tree, hf_uru_node_trackid, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      soffset += 4;
	      tf = proto_tree_add_item(sub_tree, hf_uru_vault_ref_id2, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      tf = proto_tree_add_item(sub_tree, hf_uru_node_trackid, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      soffset += 4;
	      tf = proto_tree_add_item(sub_tree, hf_uru_vault_ref_id3, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      tf = proto_tree_add_item(sub_tree, hf_uru_node_trackid, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      soffset += 4;
	      soffset += 9;
	    }
	    /* TODO: verify soffset-noffset == streamlen */
	  }
	  else if (id == 0x000a) {
	    guint16 ct, j;
	    int soffset;
	    proto_tree *sub_tree;

	    soffset = noffset;
	    sub_tree = proto_item_add_subtree(tf, ett_vault_nodelist);
	    ct = tvb_get_letohs(ntvb, soffset);
	    proto_tree_add_item(sub_tree, hf_uru_vault_nego_ct2, ntvb, soffset,
				2, TRUE);
	    proto_item_append_text(len_tf, " (%u index%s)", ct,
				   ct == 1 ? "" : "es");
	    soffset += 2;
	    for (j = 0; j < ct; j++) {
	      guint32 idx;
	      idx = tvb_get_letohl(ntvb, soffset);
	      proto_tree_add_uint_format(sub_tree, hf_uru_vault_nego_nodeidx,
					 ntvb, soffset, 4, idx, "  %u", idx);
	      tf = proto_tree_add_item(sub_tree, hf_uru_node_trackid, ntvb,
				       soffset, 4, TRUE);
	      PROTO_ITEM_SET_HIDDEN(tf);
	      soffset += 4;
	    }
	    /* TODO: verify soffset-noffset == streamlen */
	  }
	  else if (id == 0x0006) {
	    guint32 idx, ct = 0;
	    int soffset;
	    proto_tree *sub_tree, *subsub_tree;

	    soffset = noffset;
	    sub_tree = proto_item_add_subtree(tf, ett_vault_nodes);
	    while ((gint)streamlen > (soffset-noffset)) {
	      /* using one subtree means the last state change saved (when
		 leaving a packet) will apply to all of them together,
		 but the alternative's insane */
	      tf = proto_tree_add_text(sub_tree, ntvb, soffset, 0,
				       "Node");
	      subsub_tree = proto_item_add_subtree(tf, ett_vault_fullnode);
	      soffset = add_vault_node(ntvb, soffset, subsub_tree, &idx);
	      proto_item_append_text(tf, " %u", idx);
	      ct++;
	    }
	    proto_item_append_text(len_tf, " (%u node%s)", ct,
				   plurality(ct, "", "s"));
	    /* TODO: verify soffset-noffset == streamlen (not >) */
	  }
	}
	noffset += streamlen;
      }
      else if (dtype == plServerGuid) {
	proto_tree_add_item(tree, hf_uru_vault_sguid, ntvb, noffset, 8, TRUE);
	noffset += 8;
      }
      else if (dtype == plAgeLinkStruct) {
	noffset = dissect_age_link(ntvb, noffset, tree, TRUE);
      }
      /* Argh! plVaultNodeRef2 == plVaultNode */
      else if (dtype == plVaultNodeRef || dtype == plVaultNodeRef2
	       || dtype == plVaultNode || dtype == plVaultNode2) {
	/* vault nodes start with 1 or 2, then have (1 or 2) 4-byte masks,
	   then have the idx */
	/* node refs start with idx1, idx2, idx3 */
	/* so the best way I have to tell them apart is to take advantage
	   of the fact that node indexes are > 20000; heuristic but what
	   can I say? */
	guint32 unk32;

	unk32 = tvb_get_letohl(ntvb, noffset);
	if (dtype == plVaultNodeRef
	    || (dtype == plVaultNodeRef2 && !islive
		&& (curr_conv->version == POTS
		    || (curr_conv->version == UNKNOWN
			&& (unk32 != 1) && (unk32 != 2))))) {
	  proto_tree_add_item(tree, hf_uru_vault_ref_id1, ntvb, noffset,
			      4, TRUE);
	  tf = proto_tree_add_item(tree, hf_uru_node_trackid, ntvb, noffset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_vault_ref_id2, ntvb, noffset,
			      4, TRUE);
	  tf = proto_tree_add_item(tree, hf_uru_node_trackid, ntvb, noffset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_vault_ref_id3, ntvb, noffset,
			      4, TRUE);
	  tf = proto_tree_add_item(tree, hf_uru_node_trackid, ntvb, noffset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  noffset += 4;
	  add_uru_timestamp(ntvb, noffset, tree, hf_uru_vault_node_ts,
			    hf_uru_vault_node_sec, hf_uru_vault_node_usec);
	  noffset += 8;
	  proto_tree_add_item(tree, hf_uru_vault_ref_flag, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	else {
	  noffset = add_vault_node(ntvb, noffset, tree, NULL);
	}
      }
      else {
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, noffset-2, 2, 1,
				      "Can't dissect unknown data type!");
	return offset;
      }
    } /* for */
    if (cflag == 0x03) {
      if (unclen != noffset) {
	/* there was extra data */
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, noffset, unclen-noffset, 1,
				      "Extra unparsed data");
      }
      offset = offset + msglen;
    }
    else {
      offset = noffset;
    }
    if (type != NetMsgVaultTask) {
      proto_tree_add_item(tree, hf_uru_vault_ctx16, tvb, offset, 2, TRUE);
      offset += 2;
      i = tvb_get_letohs(tvb, offset);
      tf = proto_tree_add_item(tree, hf_uru_vault_res, tvb, offset, 2, TRUE);
      if (global_uru_hide_stuff && i == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      offset += 2;
    }
    else {
      proto_tree_add_item(tree, hf_uru_vault_ctx, tvb, offset, 1, TRUE);
      offset += 1;
    }
    proto_tree_add_item(tree, hf_uru_vault_mgr, tvb, offset, 4, TRUE);
    tf = proto_tree_add_item(tree, hf_uru_node_trackid, tvb, offset,
			     4, TRUE);
    PROTO_ITEM_SET_HIDDEN(tf);
    offset += 4;
    if (type != NetMsgVaultTask) {
      proto_tree_add_item(tree, hf_uru_vault_vn, tvb, offset, 2, TRUE);
      offset += 2;
    }
    return offset;
  }
  else if (type == NetMsgCreatePlayer) {
    guint32 unk1;

    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_create_avname, tvb, offset,
		       slen, str);
    MAYBE_FREE(str);
    offset += slen;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_create_gender, tvb, offset,
		       slen, str);
    MAYBE_FREE(str);
    offset += slen;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_create_fname, tvb, offset,
		       slen, str); /* friend name */
    MAYBE_FREE(str);
    offset += slen;
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_create_passkey, tvb, offset,
		       slen, str);
    MAYBE_FREE(str);
    offset += slen;
    unk1 = tvb_get_letohs(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_create_unk1, tvb, offset, 4, TRUE);
    if (global_uru_hide_stuff && unk1 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    return offset;
  }
  else if (type == NetMsgPlayerCreated) {
    proto_tree_add_item(tree, hf_uru_created_resp, tvb, offset, 1, TRUE);
    offset += 1;
    return offset;
  }
  else if (type == NetMsgDeletePlayer) {
    guint16 unk1;

    unk1 = tvb_get_letohs(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_delete_unk1, tvb, offset, 2, TRUE);
    if (global_uru_hide_stuff && unk1 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 2;
    return offset;
  }

  else if (type == NetMsgGameMessageDirected || type == NetMsgGameMessage) {
    guint32 unclen, msglen, msgflags, kinum, unk32, i;
    guint8 cflag, recipct, unk8;
    guint16 msgtype, unk16;
    gint msgstart;
    int retoffset = -1;
    
    unclen = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_gamemsg_uncsize, tvb, offset,
			     4, TRUE);
    offset += 4;
    cflag = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_uru_gamemsg_cflag, tvb, offset, 1, TRUE);
    offset += 1;
    msglen = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_gamemsg_msglen, tvb, offset, 4, TRUE);
    offset += 4;
    msgtype = tvb_get_letohs(tvb, offset);
    if (!islive) {
      proto_tree_add_item(tree, hf_uru_gamemsg_type, tvb, offset, 2, TRUE);
    }
    else {
      proto_tree_add_item(tree, hf_urulive_gamemsg_type, tvb, offset, 2, TRUE);
      msgtype = live_translate(msgtype);
    }
    offset += 2;
    if (cflag == kCompressionZlib) {
#ifdef HAVE_LIBZ
      ntvb = tvb_uncompress(tvb, offset, msglen-2);
#else
      ntvb = NULL;
#endif
      if (!ntvb) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					   tvb, offset,
					   tvb_length_remaining(tvb, offset),
					   1, "Uncompress failed!");
	PROTO_ITEM_SET_GENERATED(tf);
	return offset;
      }
      tvb_set_child_real_data_tvbuff(tvb, ntvb);
      add_new_data_source(pinfo, ntvb, "Uncompressed data");
      tvb_set_free_cb(ntvb, g_free);
      noffset = 0;
      if (tvb_length_remaining(ntvb, 0) != (gint)unclen-2) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
			    tvb, offset, msglen-2, 1,
			    "Uncompressed length doesn't match, actual: %u",
			    tvb_length_remaining(ntvb, 0));
	PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    else {
      ntvb = tvb;
      noffset = offset;
    }
    msgstart = noffset;
    /* originating object? */
    noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					 ETT_ODESC(treect), NULL,
					 TRUE, NULL, NULL, NULL,
					 hf_uru_obj_exists, 0, hf_uru_obj);
    treect++;
    unk32 = tvb_get_letohl(ntvb, noffset);
    proto_tree_add_item(tree, hf_uru_gamemsg_subobjct, ntvb, noffset,
			4, TRUE);
    noffset += 4;
    /* event ID? */
    for (i = 0; i < unk32; i++) {
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_subobj_exists,
					   1, hf_uru_subobj);
      treect++;
    }
    unk32 = tvb_get_letohl(ntvb, noffset);
    tf = proto_tree_add_item(tree, hf_uru_gamemsg_unk2, ntvb, noffset,
			     4, TRUE);
    if (global_uru_hide_stuff && unk32 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    noffset += 4;
    unk32 = tvb_get_letohl(ntvb, noffset);
    tf = proto_tree_add_item(tree, hf_uru_gamemsg_unk3, ntvb, noffset,
			     4, TRUE);
    if (global_uru_hide_stuff && unk32 == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    noffset += 4;
    msgflags = tvb_get_letohl(ntvb, noffset);
    proto_tree_add_item(tree, hf_uru_gamemsg_flags, ntvb, noffset,
			4, TRUE);
    noffset += 4;
    if (msgtype == pfKIMsg) {
      /* add uru.chat for convenience */
      tf = proto_tree_add_boolean_format(tree, hf_uru_ischat, ntvb, noffset,
					 0, 1, "chat");
      PROTO_ITEM_SET_HIDDEN(tf);

      unk8 = tvb_get_guint8(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_kimsg_unk6, ntvb, noffset,
			       1, TRUE);
      if (global_uru_hide_stuff && unk8 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 1;
      /* from here it's mostly clear what it is */
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_kimsg_sender, ntvb, noffset, slen,
			 str);
      MAYBE_FREE(str);
      noffset += slen;
      proto_tree_add_item(tree, hf_uru_kimsg_senderKI, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      if (!islive) {
	str = get_uru_string(ntvb, noffset, &slen);
      }
      else {
	str = get_uru_widestring(ntvb, noffset, &slen);
      }
      if (slen > 200+2) {
	char *buf;
	int total, sofar;

#ifdef EPHEMERAL_BUFS
	buf = ep_alloc(201);
#else
	buf = g_malloc(201);
#endif
	total = (islive ? (slen-2)/2 : slen-2);
	sofar = 0;

	memcpy(buf, str, 200);
	buf[200] = '\0';
	proto_tree_add_string(tree, hf_uru_kimsg_msg, ntvb, noffset,
			      slen, buf);
	sofar = 200;
	while (sofar < total) {
	  int thelen;
	  thelen = MIN(200, total-sofar);
	  memcpy(buf, str+sofar, thelen);
	  buf[thelen] = '\0';
	  proto_tree_add_text(tree, ntvb, noffset+(islive ? sofar*2 : sofar),
			      islive ? thelen*2 : thelen, "         %s", buf);
	  sofar += thelen;
	}
#ifndef EPHEMERAL_BUFS
	g_free(buf);
#endif
      }
      else {
	proto_tree_add_STR(tree, hf_uru_kimsg_msg, ntvb, noffset,
			   slen, str);
      }
      MAYBE_FREE(str);
      noffset += slen;
      if (islive && slen > 2) {
	/* mysterious two bytes of zeros which are only present when the
	   string is more than 0 characters long */
	unk16 = tvb_get_letohs(ntvb, noffset);
	tf = proto_tree_add_item(tree, hf_urulive_kimsg_extra, ntvb, noffset,
				 2, TRUE);
	if (global_uru_hide_stuff && unk16 == 0) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 2;
      }
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_kimsg_chatflags, ntvb, noffset,
			       2, TRUE);
      if (unk16 != 0) {
	char *c = ": ";
	proto_tree *sub_tree;

	sub_tree = proto_item_add_subtree(tf, ett_chatflags);
	if (unk16 & kRTChatPrivate) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_private, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sPrivate", c);
	  c = ",";
	}
	if (unk16 & kRTChatAdmin) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_admin, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sAdmin", c);
	  c = ",";
	}
	if (unk16 & 0x04) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_flag04, ntvb, noffset,
			      2, TRUE);
	}
	if (unk16 & kRTChatInterAge) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_interage, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sInterAge", c);
	  c = ",";
	}
	if (unk16 & kRTChatStatusMsg) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_status, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sStatusMsg", c);
	  c = ",";
	}
	if (unk16 & kRTChatNeighborsMsg) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_neighbors, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sNeighborsMsg", c);
	  c = ",";
	}
	if (unk16 & kRTChatTranslate) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_translate, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sTranslate", c);
	  c = ",";
	}
	if (unk16 & 0x80) {
	  proto_tree_add_item(sub_tree, hf_uru_kimsg_flag80, ntvb, noffset,
			      2, TRUE);
	}
	proto_tree_add_item(sub_tree, hf_uru_kimsg_channel, ntvb, noffset,
			    2, TRUE);
	if (unk16 & 0xff00) {
	  proto_item_append_text(tf, " Channel: %d", unk16 >> 8);
	}
      }
      noffset += 2;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_kimsg_unk7, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_kimsg_unk8, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_kimsg_unk9, ntvb, noffset,
			       2, TRUE);
      if (global_uru_hide_stuff && unk16 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 2;
    }
    else if (msgtype == plLinkingMgrMsg || msgtype == plLinkToAgeMsg) {
      if (msgtype == plLinkToAgeMsg) {
	unk8 = tvb_get_guint8(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_linkmsg_unk2, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
	noffset = dissect_age_link(ntvb, noffset, tree, TRUE);
	str = get_uru_string(ntvb, noffset, &slen);
	proto_tree_add_STR(tree, hf_uru_linkmsg_str, ntvb, noffset,
			   slen, str);
	MAYBE_FREE(str);
	noffset += slen;
      }
      else {
	gint32 submsglen, suboffset;
	unk32 = tvb_get_letohl(ntvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_linkmsg_unk4, ntvb, noffset,
				 4, TRUE);
	if (global_uru_hide_stuff && unk32 == 0x00000001) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 4;
	unk32 = tvb_get_letohl(ntvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_linkmsg_unk5, ntvb, noffset,
				 4, TRUE);
	if (global_uru_hide_stuff && unk32 == 0x00000003) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 4;
	unk16 = tvb_get_letohs(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_linkmsg_unk6, ntvb, noffset,
			    2, TRUE);
	noffset += 2;
	submsglen = tvb_get_letohl(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_linkmsg_msglen, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	suboffset = noffset;
	unk32 = tvb_get_letohl(ntvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_linkmsg_unk7, ntvb, noffset,
				 4, TRUE);
	if (global_uru_hide_stuff && unk32 == 0x00000001) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_linkmsg_unk8, ntvb, noffset,
			    2, TRUE);
	noffset += 2;
	unk8 = tvb_get_guint8(ntvb, noffset);
	tf = proto_tree_add_item(tree, hf_uru_linkmsg_unk9, ntvb, noffset,
				 1, TRUE);
	if (global_uru_hide_stuff && unk32 == 0x00) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset += 1;
	proto_tree_add_item(tree, hf_uru_linkmsg_reqki, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	if (suboffset+submsglen != noffset) {
	  if (suboffset+submsglen > noffset) {
	    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					  ntvb, noffset,
					  suboffset+submsglen-noffset, 1,
					  "Lengths don't match, actual: %u",
					  noffset-suboffset);
	  }
	  else {
	    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					  ntvb, suboffset+submsglen,
					  noffset-(suboffset+submsglen), 1,
					  "Lengths don't match, actual: %u",
					  noffset-suboffset);
	  }
	  PROTO_ITEM_SET_GENERATED(tf);
	}
      }
    }
    else if (msgtype == plNotifyMsg) {
      guint32 eventct, event;

      proto_tree_add_item(tree, hf_uru_notify_unk2, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_notify_state, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_notify_unk4, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      eventct = tvb_get_letohl(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_notify_eventct, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      for (i = 0; i < eventct; i++) {
	event = tvb_get_letohl(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_notify_event0, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	if (event == kOfferLinkingBookEvent) {
	  /* next is an URUOBJECTREF (event[1]) then a number (event[2]) */
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  proto_tree_add_item(tree, hf_uru_notify_offer_event2, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_offer_event3, ntvb, noffset,
			      4, TRUE); /* this is the recipient's KI number */
	  noffset += 4;
	  /* end */
	}
	else if (event == kMultiStageEvent) {
	  /* next is stageNum (event[1]) then multistage event (event[2])
	     then an URUOBJECTREF: an avatar */
	  proto_tree_add_item(tree, hf_uru_notify_multistg_num, ntvb,
			      noffset, 4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_multistg_event, ntvb,
			      noffset, 4, TRUE);
	  noffset += 4;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  /* end */
	}
	else if (event == kPickedEvent) {
	  /* next is two URUOBJECTREFs then a byte then 12 bytes */
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  proto_tree_add_item(tree, hf_uru_notify_picked_event3, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_notify_picked_x, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_picked_y, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_picked_z, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  /* end */
	}
	else if (event == kCollisionEvent) {
	  /* next is a 1-byte value: 1 for enter, 0 for leave I guess,
	     then two URUOBJECTREFs */
	  proto_tree_add_item(tree, hf_uru_notify_coll_event1, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	}
	else if (event == kContainedEvent) {
	  /* next is an URUOBJECTREF then I dunno */
	  if (msgflags & GameMsgFlag10) {
	    proto_tree_add_item(tree, hf_uru_notify_contain_ex, ntvb, noffset,
				1, TRUE);
	    noffset += 1;
	  }
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  if (msgflags & GameMsgFlag10) {
	    /* what the heck... */
	    proto_tree_add_item(tree, hf_uru_notify_contain_event2s, ntvb,
				noffset, 1, TRUE);
	    noffset += 1;
	  }
	  else {
	    proto_tree_add_item(tree, hf_uru_notify_contain_event2, ntvb,
				noffset, 2, TRUE);
	    noffset += 2;
	  }
	}
	else if (event == kVariableEvent) {
	  /* next is a string: variable name, then an int then a float */
	  str = get_uru_string(ntvb, noffset, &slen);
	  proto_tree_add_STR(tree, hf_uru_notify_var_var, ntvb, noffset,
			     slen, str);
	  MAYBE_FREE(str);
	  noffset += slen;
	  unk32 = tvb_get_letohl(ntvb, noffset);
	  proto_tree_add_item(tree, hf_uru_notify_var_type, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  if (unk32 == kVarNumberType) {
	    proto_tree_add_item(tree, hf_uru_notify_var_event3f, ntvb, noffset,
				4, TRUE);
	    noffset += 4;
	  }
	  else if (unk32 == kVarKeyType) {
	    /* GUESS */
	    noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
						 ETT_ODESC(treect), NULL,
						 TRUE, NULL, NULL, NULL,
						 hf_uru_subobj_exists,
						 1, hf_uru_notify_var_event3o);
	    treect++;
	  }
	  proto_tree_add_item(tree, hf_uru_notify_var_event4, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  /* end */
	}
	else if (event == kResponderStateEvent) {
	  proto_tree_add_item(tree, hf_uru_notify_respst_state, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  /* end */
	}
	else if (event == kFacingEvent) {
	  /* next is two URUOBJECTREFs then a byte */
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  proto_tree_add_item(tree, hf_uru_notify_facing_event3, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_facing_event4, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	else if (event == kActivateEvent) {
	  proto_tree_add_item(tree, hf_uru_notify_act_event1, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_notify_act_event2, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  /* end */
	}
	else if (event == UnknownNotifyEventType) {
	  proto_tree_add_item(tree, hf_uru_notify_num13_ki, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_notify_num13_event2, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	  /* end */
	}
	else if (event == kSpawnedEvent) {
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	  noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					       ETT_ODESC(treect), NULL,
					       TRUE, NULL, NULL, NULL,
					       hf_uru_notify_objexists,
					       1, hf_uru_notify_obj);
	  treect++;
	}
	else {
	  /* ControlKey, Callback, ClickDrag, Book */
	}
      }
    }
    else if (msgtype == plInputIfaceMgrMsg) {
      proto_tree_add_item(tree, hf_uru_iface_unk1, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      proto_tree_add_item(tree, hf_uru_iface_float, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_iface_str1, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_iface_str2, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_iface_str3, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_iface_objexists,
					   1, hf_uru_iface_obj);
      treect++;
    }
    else if (msgtype == plServerReplyMsg) {
      proto_tree_add_item(tree, hf_uru_srply_reply, ntvb, noffset, 4, TRUE);
      noffset += 4;
    }
    else if (msgtype == plAvatarInputStateMsg) {
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_avstate_flags, ntvb, noffset,
			       2, TRUE);
      if (unk16 == 0) {
	proto_item_append_text(tf, ": Idle");
      }
      else {
	char *c = ": ";
	proto_tree *sub_tree;

	sub_tree = proto_item_add_subtree(tf, ett_inputflags);
	if (unk16 & InputForward) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_fwd, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sForward", c);
	  c = ",";
	}
	if (unk16 & InputBack) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_back, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sBackward", c);
	  c = ",";
	}
	if (unk16 & InputTurnLeft) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_left, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sTurnLeft", c);
	  c = ",";
	}
	if (unk16 & InputTurnRight) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_right, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sTurnRight", c);
	  c = ",";
	}
	if (unk16 & InputSidestepLeft) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_sidel, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sSidestepLeft", c);
	  c = ",";
	}
	if (unk16 & InputSidestepRight) {
	  proto_tree_add_item(sub_tree, hf_uru_avstate_sider, ntvb, noffset,
			      2, TRUE);
	  proto_item_append_text(tf, "%sSidestepRight", c);
	  c = ",";
	}
	/* TODO: other flags */
	if (unk16 & ~(InputForward|InputBack|InputTurnLeft|InputTurnRight
		      |InputSidestepLeft|InputSidestepRight)) {
	  tf = proto_tree_add_boolean_format(tree,
					     hf_uru_incomplete_dissection,
					     ntvb, noffset, 2, 1,
					     "Unknown AvatarInputState flags");
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
      }
      noffset += 2;
    }
    else if (msgtype == plLinkEffectsTriggerMsg) {
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_linkeff_unk0, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk8 = tvb_get_guint8(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_linkeff_unk1, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_linkeff_objexists,
					   1, hf_uru_linkeff_obj);
      treect++;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_linkeff_unk2, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_linkeff_effexists,
					   1, hf_uru_linkeff_eff);
      treect++;
    }
    else if (msgtype == plClothingMsg) {
      /* 0x24 when transmitting first line in clone file after clothing items,
	 0x44 when transmitting the 5 last lines */
      /* 0x1 when flag below is 0, 0x18 when flag is 8, 0x1c when flag is 9
	 (changing in closet) */
      proto_tree_add_item(tree, hf_uru_clothing_flags, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
      unk8 = tvb_get_guint8(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_clothing_present, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      if (unk8) {
	noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					     ETT_ODESC(treect), NULL,
					     TRUE, NULL, NULL, NULL,
					     hf_uru_clothing_objexists,
					     1, hf_uru_clothing_item);
	treect++;
      }
      proto_tree_add_item(tree, hf_uru_clothing_r, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_clothing_g, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_clothing_b, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_clothing_o, ntvb, noffset, 4, TRUE);
      noffset += 4;
      /* index when transmitting the last 5 lines in the clone file; else
	 a flag: for actual clothing items, 8 = primary tint,
	 9 = secondary tint, 0 = wear it? */
      proto_tree_add_item(tree, hf_uru_clothing_flag, ntvb, noffset, 4, TRUE);
      noffset += 4;
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_clothing_unk3, ntvb, noffset,
			       2, TRUE);
      if (global_uru_hide_stuff && unk16 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 2;
    }
    else if (msgtype == pfClimbingWallMsg || msgtype == plClimbEventMsg
	     || msgtype == plClimbEventMsg2) {
      /* plClimbEventMsg has no body in UU, but if we had the wall in PotS,
	 then it would be plClimbingWallMsg2 and plClimbEventMsg2 would have
	 no body */
      if ((msgtype == plClimbEventMsg && (msgstart+msglen-2)-noffset < 3)
	  || msgtype == plClimbEventMsg2) {
	/* no body */
      }
      else {
	guint8 wallmsg;
	wallmsg = tvb_get_guint8(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_wall_msgtype, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
	if (wallmsg == kRequestGameState) {
	  proto_tree_add_item(tree, hf_uru_wall_unk0, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	}
	else if (wallmsg == kTotalGameState) {
	  proto_tree_add_item(tree, hf_uru_wall_sstate, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	  proto_tree_add_item(tree, hf_uru_wall_nstate, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	}
	else if (wallmsg == kSetBlockerNum) {
	  /* bl is 1 when setting the count, 0 when clearing the count to 0 */
	  proto_tree_add_item(tree, hf_uru_wall_bl, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_wall_blct, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	else if (wallmsg == kAddBlocker || wallmsg == kRemoveBlocker) {
	  proto_tree_add_item(tree, hf_uru_wall_blidx, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_wall_side, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	else if (wallmsg == kNewState) {
	  proto_tree_add_item(tree, hf_uru_wall_state, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_wall_side, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	else if (wallmsg == kEndGameState) {
	  /* TODO: find one */
	}
      }
    }
    else if (msgtype == plWarpMsg) { /* adminKI tricks */
      gint i, j;
      gfloat val;

      if (islive) {
	gint present;

	present = tvb_get_guint8(ntvb, noffset);
	/* XXX shouldn't really be hf_uru_obj_exists but it's convenient */
	proto_tree_add_item(tree, hf_uru_obj_exists, ntvb, noffset, 1, TRUE);
	noffset += 1;
	/* XXX also I do not know what this byte really means - could be a
	   format specifier too*/
	if (present) {
	  proto_tree_add_item(tree, hf_uru_warp_matrix, ntvb, noffset,
			      64, FALSE);
	  for (i = 0; i < 4; i++) {
	    tf = proto_tree_add_text(tree, ntvb, noffset, 16, " [ ");
	    for (j = 0; j < 4; j++) {
	      val = tvb_get_letohieee_float(ntvb, noffset);
	      proto_item_append_text(tf, "%11f ", val);
	      noffset += 4;
	    }
	    proto_item_append_text(tf, "]");
	  }
	}
      }
      proto_tree_add_item(tree, hf_uru_warp_unk, ntvb, noffset, 4, TRUE);
      noffset += 4;
    }
    else if (msgtype == plSubWorldMsg) {
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_subworld_objexists,
					   1, hf_uru_subworld_obj);
      treect++;
    }
    else if (msgtype == plEnableMsg) {
      proto_tree_add_item(tree, hf_uru_enable_unk0, ntvb, noffset, 4, TRUE);
      noffset += 4;
      /* this is 0xa for physics.enable(), 0x9 for physics.disable() */
      proto_tree_add_item(tree, hf_uru_enable_unk1, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_enable_unk2, ntvb, noffset, 4, TRUE);
      noffset += 4;
    }
    else if (msgtype == plAvSeekMsg) {
      proto_tree_add_item(tree, hf_uru_avseek_unk0, ntvb, noffset, 2, TRUE);
      noffset += 2;
      proto_tree_add_item(tree, hf_uru_avseek_tox, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_toy, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_toz, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_fmx, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_fmy, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_fmz, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_unk1, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_unk2, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_avseek_unk3, ntvb, noffset, 4, TRUE);
      noffset += 4;
    }
    else if (msgtype == plAvTaskMsg) {
      unk8 = tvb_get_guint8(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_avtask_unk0, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      unk16 = tvb_get_letohs(ntvb, noffset);
      if (!islive) {
	proto_tree_add_item(tree, hf_uru_avtask_type, ntvb, noffset, 2, TRUE);
      }
      else {
	proto_tree_add_item(tree, hf_urulive_avtask_type, ntvb, noffset,
			    2, TRUE);
	unk16 = live_translate(unk16);
      }
      noffset += 2;
      if (unk16 == plAvAnimTask
	  || unk16 == plAvOneShotLinkTask || unk16 == plAvOneShotLinkTask2) {
	str = get_uru_string(ntvb, noffset, &slen);
	proto_tree_add_STR(tree, hf_uru_avtask_name, ntvb, noffset,
			   slen, str);
	MAYBE_FREE(str);
	noffset += slen;
	if (unk16 == plAvOneShotLinkTask
	    || unk16 == plAvOneShotLinkTask2) {
	  str = get_uru_string(ntvb, noffset, &slen);
	  proto_tree_add_STR(tree, hf_uru_avtask_action, ntvb, noffset,
			     slen, str);
	  MAYBE_FREE(str);
	  noffset += slen;
	}
      }
      else if (unk16 == plAvTaskBrain) {
	/* TODO: figure out brains */
#ifdef DEVELOPMENT
	guint32 count, i;
#endif

	unk16 = tvb_get_letohs(ntvb, noffset);
	if (!islive) {
	  proto_tree_add_item(tree, hf_uru_avtask_braintype, ntvb, noffset,
			      2, TRUE);
	}
	else {
	  proto_tree_add_item(tree, hf_urulive_avtask_braintype, ntvb, noffset,
			      2, TRUE);
	  unk16 = live_translate(unk16);
	}
	noffset += 2;
#ifdef DEVELOPMENT
	proto_tree_add_item(tree, hf_uru_avtask_brainstage, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
	proto_tree_add_item(tree, hf_uru_brain_unk0, ntvb, noffset, 4, TRUE);
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_avtask_brainunk1, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_avtask_braintime1, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_brain_unk1, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_avtask_braintime2, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	count = tvb_get_letohl(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_avtask_stagect, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	for (i = 0; i < count; i++) {
	  if (!islive) {
	    proto_tree_add_item(tree, hf_uru_avtask_stagetype, ntvb,
				noffset, 2, TRUE);
	  }
	  else {
	    proto_tree_add_item(tree, hf_urulive_avtask_stagetype, ntvb,
				noffset, 2, TRUE);
	  }
	  noffset += 2;
	  str = get_uru_string(ntvb, noffset, &slen);
	  proto_tree_add_STR(tree, hf_uru_avtask_stagename, ntvb,
			     noffset, slen, str);
	  MAYBE_FREE(str);
	  noffset += slen;

	  proto_tree_add_item(tree, hf_uru_avtask_brainunk0, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	  proto_tree_add_item(tree, hf_uru_brain_unk0, ntvb, noffset, 4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_brain_unk1, ntvb, noffset, 4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_brain_unk2, ntvb, noffset, 4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_brain_unk2, ntvb, noffset, 4, TRUE);
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_avtask_brainunk1, ntvb, noffset,
			      4, TRUE); /* signed */
	  noffset += 4;
	  proto_tree_add_item(tree, hf_uru_avtask_bytes, ntvb, noffset,
			      23, TRUE); /* lots of zeros */
	  noffset += 23;
	}
	proto_tree_add_item(tree, hf_uru_avtask_bytes, ntvb, noffset,
			    8, TRUE); /* lots of zeros */
	noffset += 8;
	proto_tree_add_item(tree, hf_uru_brain_unk2, ntvb, noffset, 4, TRUE);
	noffset += 4;
	proto_tree_add_item(tree, hf_uru_avtask_bytes, ntvb, noffset,
			    15, TRUE);
	noffset += 15;
#endif /* DEVELOPMENT */
      }
      else if (unk16 == plAnimCmdMsg) {
	/* TODO */
      }
    }
    else if (msgtype == plAvOneShotMsg) { /* adminKI tricks */
      unk8 = tvb_get_guint8(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_oneshot_unk0, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_oneshot_objexists,
					   1, hf_uru_oneshot_obj);
      treect++;
      proto_tree_add_item(tree, hf_uru_oneshot_unk1, ntvb, noffset, 4, TRUE);
      noffset += 4;
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_oneshot_unk2, ntvb, noffset,
			       2, TRUE);
      if (global_uru_hide_stuff && unk16 == 0x0001) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 2;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_oneshot_unk3, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0x000000f0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_oneshot_unk4, ntvb, noffset,
			       2, TRUE);
      if (global_uru_hide_stuff && unk16 == 0x0002) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 2;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_oneshot_anim, ntvb, noffset,
			 slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      unk16 = tvb_get_letohs(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_oneshot_unk5, ntvb, noffset,
			       2, TRUE);
      if (global_uru_hide_stuff && unk16 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 2;
    }
    else if (msgtype == plControlEventMsg) { /* adminKI tricks */
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk0, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0xffffffff) { /* -1 */
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk1, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0x00000028) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk2, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0x00000001) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk3, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0x3f800000) { /* 1.0 */
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk4, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk5, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_ctrlevt_unk6, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_ctrlevt_cmd, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
    }
    else if (msgtype == plMultistageModMsg) {
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_multimod_unk0, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 1) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      unk32 = tvb_get_letohl(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_multimod_unk1, ntvb, noffset,
			       4, TRUE);
      if (global_uru_hide_stuff && unk32 == 1) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_multimod_unk2, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
      proto_tree_add_item(tree, hf_uru_multimod_unk3, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
    }
    else if (msgtype == plClimbMsg || msgtype == plClimbMsg2) {
      proto_tree_add_item(tree, hf_uru_climb_unk0, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_climb_unk1, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_climb_unk2, ntvb, noffset, 1, TRUE);
      noffset += 1;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_climb_objexists,
					   1, hf_uru_climb_obj);
      treect++;
    }
    else if (msgtype == plPseudoLinkEffectMsg
	     || msgtype == plPseudoLinkEffectMsg2) {
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_fakelink_destexists,
					   1, hf_uru_fakelink_dest);
      treect++;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_fakelink_objexists,
					   1, hf_uru_fakelink_obj);
      treect++;
    }
    else if (msgtype == plAvBrainGenericMsg) {
      proto_tree_add_item(tree, hf_uru_brain_unk0, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_brain_unk1, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_brain_unk2, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_brain_unk3, ntvb, noffset, 3, TRUE);
      noffset += 3;
      proto_tree_add_item(tree, hf_uru_brain_time, ntvb, noffset, 4, TRUE);
      noffset += 4;
    }
    else if (msgtype == plAvCoopMsg || msgtype == plAvCoopMsg2) {
      /* book sharing */
      guint16 typecode;
#ifdef DEVELOPMENT
      guint32 stagect, i;
      int j;
#endif

      proto_tree_add_item(tree, hf_uru_share_unk0, ntvb, noffset, 1, TRUE);
      noffset += 1;
      typecode = tvb_get_letohs(ntvb, noffset);
      proto_tree_add_item(tree, hf_uru_share_type, ntvb, noffset, 2, TRUE);
      noffset += 2;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_share_sharerexists,
					   1, hf_uru_share_sharer);
      treect++;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_share_shareeexists,
					   1, hf_uru_share_sharee);
      treect++;
      /* this is the share message + 1 */
#ifdef DEVELOPMENT
      proto_tree_add_item(tree, hf_uru_share_unktype, ntvb, noffset, 2, TRUE);
      noffset += 2;
      proto_tree_add_item(tree, hf_uru_share_unk1, ntvb, noffset, 1, TRUE);
      noffset += 1;
      for (j = 0; j < 2; j++) {
	proto_tree_add_item(tree, hf_uru_share_unkflag, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					     ETT_ODESC(treect), NULL,
					     TRUE, NULL, NULL, NULL,
					     hf_uru_share_avmgrexists,
					     1, hf_uru_share_avmgr);
	treect++;
	/* ??? cheat for now */
	proto_tree_add_item(tree, hf_uru_share_bytes, ntvb, noffset,
			    16, FALSE);
	noffset += 16;
	stagect = tvb_get_letohl(ntvb, noffset);
	proto_tree_add_item(tree, hf_uru_share_stagect, ntvb, noffset,
			    4, TRUE);
	noffset += 4;
	for (i = 0; i < stagect; i++) {
	  proto_tree_add_item(tree, hf_uru_share_stagetype, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	  str = get_uru_string(ntvb, noffset, &slen);
	  proto_tree_add_STR(tree, hf_uru_share_stagename, ntvb, noffset,
			     slen, str);
	  MAYBE_FREE(str);
	  noffset += slen;
	  /* ??? cheat for now */
	  proto_tree_add_item(tree, hf_uru_share_stagebytes, ntvb, noffset,
			      44, FALSE);
	  noffset += 44;
	}
	/* ??? cheat for now */
	proto_tree_add_item(tree, hf_uru_share_bytes, ntvb, noffset,
			    27, FALSE);
	noffset += 27;
	proto_tree_add_item(tree, hf_uru_share_fromki, ntvb, noffset, 4, TRUE);
	noffset += 4;
	for (i = 0; i < stagect; i++) {
	  proto_tree_add_item(tree, hf_uru_share_stageunk, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;
	}
	proto_tree_add_item(tree, hf_uru_share_unk2, ntvb, noffset, 1, TRUE);
	noffset += 1;
	noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					     ETT_ODESC(treect), NULL,
					     TRUE, NULL, NULL, NULL,
					     hf_uru_share_keyexists,
					     1, hf_uru_share_key);
	treect++;
	/* ??? cheat for now */
	proto_tree_add_item(tree, hf_uru_share_bytes, ntvb, noffset, 4, FALSE);
	noffset += 4;
      }
      /* ??? cheat for now */
      proto_tree_add_item(tree, hf_uru_share_bytes, ntvb, noffset, 8, FALSE);
      noffset += 8;
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_share_netmgrexists,
					   1, hf_uru_share_netmgr);
      treect++;
      /* ??? cheat for now */
      proto_tree_add_item(tree, hf_uru_share_bytes, ntvb, noffset, 13, FALSE);
      noffset += 13;
      noffset = dissect_age_link(ntvb, noffset, tree, TRUE);
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_share_str0, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      str = get_uru_string(ntvb, noffset, &slen);
      proto_tree_add_STR(tree, hf_uru_share_strc, ntvb, noffset, slen, str);
      MAYBE_FREE(str);
      noffset += slen;
      proto_tree_add_item(tree, hf_uru_share_unk4, ntvb, noffset, 1, TRUE);
      noffset += 1;
      proto_tree_add_item(tree, hf_uru_share_ki, ntvb, noffset, 4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_share_unk5, ntvb, noffset, 3, TRUE);
      noffset += 3;
#endif /* DEVELOPMENT */
    }
    else if (msgtype == plShiftMassMsg || msgtype == plTorqueMsg
	     || msgtype == plImpulseMsg || msgtype == plOffsetImpulseMsg
	     || msgtype == plAngularImpulseMsg || msgtype == plForceMsg
	     || msgtype == plOffsetForceMsg) { /* python tricks */
      gfloat x, y, z;
      x = tvb_get_letohieee_float(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_physical_vx, ntvb, noffset,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      noffset += 4;
      y = tvb_get_letohieee_float(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_physical_vy, ntvb, noffset,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      noffset += 4;
      z = tvb_get_letohieee_float(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_physical_vz, ntvb, noffset,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      noffset += 4;
      proto_tree_add_none_format(tree, hf_uru_physical_v, ntvb,
				 noffset-12, 12,
				 "Vector: [%f %f %f]", x, y, z);
    }
    else if (msgtype == plDampMsg) { /* python tricks */
      /* no body! */
    }
    else if (msgtype == plAvEnableMsg) { /* adminKI tricks */
      unk8 = tvb_get_guint8(ntvb, noffset);
      tf = proto_tree_add_item(tree, hf_uru_avenable_unk0, ntvb, noffset,
			       1, TRUE);
      if (global_uru_hide_stuff && unk8 == 0) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      noffset += 1;
      proto_tree_add_item(tree, hf_uru_avenable_en, ntvb, noffset, 1, TRUE);
      noffset += 1;
    }
    else if (msgtype == plParticleTransferMsg) {
      noffset = dissect_uru_object_subtree(ntvb, noffset, tree,
					   ETT_ODESC(treect), NULL,
					   TRUE, NULL, NULL, NULL,
					   hf_uru_particle_objexists,
					   1, hf_uru_particle_obj);
      treect++;
      proto_tree_add_item(tree, hf_uru_particle_count, ntvb, noffset, 2, TRUE);
      noffset += 2;
    }
    else if (msgtype == plParticleKillMsg) {
      proto_tree_add_item(tree, hf_uru_particle_killnum, ntvb, offset,
			  4, TRUE);
      noffset += 4;
      proto_tree_add_item(tree, hf_uru_particle_killtime, ntvb, offset,
			  4, TRUE);
      noffset += 4;
      /* flags: kParticleKillImmortalOnly and kParticleKillPercentage */
      proto_tree_add_item(tree, hf_uru_particle_killflags, ntvb, offset,
			  1, TRUE);
      noffset += 1;
    }
#ifdef DEVELOPMENT
    else if (0 && msgtype == plSetNetGroupIDMsg) {
      /* ??? cheat for now */
      proto_tree_add_item(tree, hf_urulive_groupid_bytes, ntvb, noffset,
			  7, TRUE);
      noffset += 7;
    }
#endif
    else {
      proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
			ntvb, noffset, (msgstart+msglen-2)-noffset, 1,
			"Data (dissection of this type not implemented)");
      if (cflag == kCompressionZlib) {
	retoffset = msgstart;
      }
      else {
	retoffset = noffset;
      }
      noffset = msgstart+msglen-2;
    }
#ifdef DEVELOPMENT
    if ((cflag == kCompressionZlib && (guint)noffset < unclen-2)
	|| (cflag != kCompressionZlib && msgstart+msglen-2 > (guint)noffset)) {
	    tvbuff_t *ftvb;
	    gint bufsize, i;
	    guint8 *newbuf;

	    bufsize = tvb_length_remaining(ntvb, noffset);
	    newbuf = tvb_memdup(ntvb, noffset, bufsize);
	    for (i = 0; i < bufsize; i++) {
	      newbuf[i] = ~newbuf[i];
	    }
	    ftvb = tvb_new_real_data(newbuf, bufsize, bufsize);
	    tvb_set_child_real_data_tvbuff(ntvb, ftvb);
	    tvb_set_free_cb(ftvb, g_free);
	    add_new_data_source(pinfo, ftvb, "Bit-flipped data");
    }
#endif
    if (cflag == kCompressionZlib) {
      if (noffset != (gint)unclen-2) {
	/* there was extra data */
	proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, noffset, (unclen-2)-noffset, 1,
				      "Extra unparsed data");
      }
    }
    else {
      if (msgstart+msglen-2 != (guint)noffset) {
	if (msgstart+msglen-2 > (guint)noffset) {
	  tf = proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
					ntvb, noffset,
					(msgstart+msglen-2)-noffset, 1,
					"Lengths don't match, actual: %u",
					(noffset-msgstart)+2);
	}
	else {
	  tf = proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
					ntvb, msgstart+msglen-2,
					noffset-(msgstart+msglen-2), 1,
					"Lengths don't match, actual: %u",
					(noffset-msgstart)+2);
	}
	PROTO_ITEM_SET_GENERATED(tf);
      }
    }
    offset += msglen-2;

    proto_tree_add_item(tree, hf_uru_gamemsg_endthing, tvb, offset, 1, TRUE);
    offset += 1;
    if (type == NetMsgGameMessageDirected) {
      /* start of recipients list */
      recipct = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_uru_directed_recipct, tvb, offset, 1, TRUE);
      offset += 1;
      if (tvb_length_remaining(tvb, offset) < (4*recipct)) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, tvb,
				      offset,
				      tvb_length_remaining(tvb, offset), 1,
				      "Not enough recipients");
	PROTO_ITEM_SET_GENERATED(tf);
	return offset;
      }
      for (i = 0; i < recipct; i++) {
	kinum = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_uru_directed_recip, tvb, offset,
				   4, kinum, "  %u", kinum);
	offset += 4;
      }
    }
    if (retoffset >= 0) {
      return retoffset;
    }
    else {
      return offset;
    }
  }
  else if (type == NetMsgRelevanceRegions) {
    guint32 unk32;
    proto_tree *sub_tree;

    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_relevance_len1, tvb, offset,
			     4, TRUE);
    if (global_uru_hide_stuff && unk32 == 1) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_relevance_occupied, tvb, offset,
			     4, TRUE);
    sub_tree = proto_item_add_subtree(tf, ett_rel_occupied);
    if (unk32 & cRelRegDefaultMaybe) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_mystery, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegBridgeStairs) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_bridgestairs, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegConcertHall) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_concerthall, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegCanyon) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_canyon, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegCaveTJunction) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_tjunction, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegCourtyard) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_courtyard, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegDakotahAlley) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_takotahalley, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegMuseumAlley) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_museumalley, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegFerry) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_ferry, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegGreatStair) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_greatstair, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegKadishGallery) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_kadishgallery, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegKahloPub) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_kahlopub, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryWalk) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_librarywalk, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryStairs) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_librarystairs, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryExt) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_libraryext, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegPalace01) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_palace01, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & cRelRegPalace02) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_palace02, tvb,
			  offset, 4, TRUE);
    }
    if (unk32 & 0xfffe0000) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_occ_unknown, tvb,
			  offset, 4, TRUE);
    }
    offset += 4;
    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_relevance_len2, tvb, offset,
			     4, TRUE);
    if (global_uru_hide_stuff && unk32 == 1) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 4;
    unk32 = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_relevance_interesting, tvb, offset,
			     4, TRUE);
    sub_tree = proto_item_add_subtree(tf, ett_rel_occupied);
    if (unk32 & cRelRegDefaultMaybe) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_mystery,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegBridgeStairs) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_bridgestairs,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegConcertHall) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_concerthall,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegCanyon) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_canyon,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegCaveTJunction) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_tjunction,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegCourtyard) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_courtyard,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegDakotahAlley) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_takotahalley,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegMuseumAlley) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_museumalley,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegFerry) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_ferry,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegGreatStair) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_greatstair,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegKadishGallery) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_kadishgallery,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegKahloPub) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_kahlopub,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryWalk) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_librarywalk,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryStairs) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_librarystairs,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegLibraryExt) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_libraryext,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegPalace01) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_palace01,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & cRelRegPalace02) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_palace02,
			  tvb, offset, 4, TRUE);
    }
    if (unk32 & 0xfffe0000) {
      proto_tree_add_item(sub_tree, hf_uru_relevance_interesting_unknown,
			  tvb, offset, 4, TRUE);
    }
    offset += 4;
    return offset;
  }
  else if (type == NetMsgGetPublicAgeList) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_pubage_name, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    return offset;
  }
  else if (type == NetMsgPublicAgeList) {
    guint16 count, i;

    count = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_uru_pubage_ct, tvb, offset, 2, TRUE);
    offset += 2;
    for (i = 0; i < count; i++) {
      offset = dissect_age_link(tvb, offset, tree, FALSE);
    }
    count = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_uru_pubage_popct, tvb, offset, 2, TRUE);
    offset += 2;
    for (i = 0; i < count; i++) {
      proto_tree_add_item(tree, hf_uru_pubage_pop, tvb, offset, 4, TRUE);
      offset += 4;
    }
    return offset;
  }
  else if (type == NetMsgPython) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_python_contents, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
    offset = dissect_uru_object_subtree(tvb, offset, tree,
					ETT_ODESC(treect), NULL,
					TRUE, NULL, NULL, NULL,
					hf_uru_python_objexists,
					0, hf_uru_python_obj);
    treect++;
    return offset;

  }
  return 0;
}

/* returns new offset */
static gint
dissect_age_link(tvbuff_t *tvb, gint offset, proto_tree *tree, gboolean full)
{
  proto_item *tf;
  proto_tree *sub_tree = NULL;
  guint16 flags = 0;
  guint8 contents;
  guint32 mask;
  guint slen;
  char *str;

  if (full) {
    /* Almlys thinks flags ("mask") is one byte and I guess with a zero
       afterwards */
    flags = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_uru_age_flags, tvb, offset, 2, TRUE);
    offset += 2;
  }
  contents = tvb_get_guint8(tvb, offset);
  tf = proto_tree_add_item(tree, hf_uru_age_contents, tvb, offset, 1, TRUE);
  sub_tree = proto_item_add_subtree(tf, ett_agecontents);
  proto_tree_add_item(sub_tree, hf_uru_age_cfname, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_ciname, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_cguid, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_cuname, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_cinstance, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_cdname, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_clang, tvb, offset, 1, TRUE);
  proto_tree_add_item(sub_tree, hf_uru_age_cunk, tvb, offset, 1, TRUE);
  offset += 1;
  if (contents & 0x02) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_fname, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (contents & 0x01) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_iname, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (contents & 0x04) {
    if (!islive) {
      proto_tree_add_item(tree, hf_uru_age_guid, tvb, offset, 8, FALSE);
      offset += 8;
    }
    else {
      tf = proto_tree_add_item(tree, hf_urulive_vault_ageUUID, tvb, offset,
			  16, FALSE);
      append_uru_uuid(tf, tvb, offset);
      offset += 16;
    }
  }
  if (contents & 0x08) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_uname, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (contents & 0x10) {
    proto_tree_add_item(tree, hf_uru_age_instance, tvb, offset, 4, TRUE);
    offset += 4;
  }
  if (contents & 0x20) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_dname, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (contents & 0x40) {
    proto_tree_add_item(tree, hf_uru_age_lang, tvb, offset, 4, TRUE);
    offset += 4;
  }
  if (!full) {
    return offset;
  }
  proto_tree_add_item(tree, hf_uru_age_rules, tvb, offset, 1, TRUE);
  offset += 1;
  mask = tvb_get_letohl(tvb, offset);
  tf = proto_tree_add_item(tree, hf_uru_age_unk1, tvb, offset, 4, TRUE);
  if (global_uru_hide_stuff && mask == 0x00000001) {
    PROTO_ITEM_SET_HIDDEN(tf);
  }
  offset += 4;
  mask = tvb_get_letohl(tvb, offset);
  tf = proto_tree_add_item(tree, hf_uru_age_spawncts, tvb, offset, 4, TRUE);
  /* this is "always" 7, so I don't know which flags are which */
  if (global_uru_hide_stuff && mask == 0x00000007) {
    PROTO_ITEM_SET_HIDDEN(tf);
  }
  offset += 4;
  /* I am just guessing on the flags but this does mean that if they are
     not all set we won't bomb, they just might be mislabeled */
  if (mask & 0x01) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_spawnpt, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask & 0x02) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_linkpt, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask & 0x04) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_camera, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (flags & 0x10) {
    proto_tree_add_item(tree, hf_uru_age_unk2, tvb, offset, 1, TRUE);
    offset += 1;
  }
  if (flags & 0x40) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_age_extra, tvb, offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  return offset;
}

static gint
dissect_sdl_msg(tvbuff_t *tvb, gint offset, proto_tree *tree, gint bufend) {
  char *sdlname;
  guint slen;
  guint16 version;
  struct sdl_info *sdl;

  sdlname = get_uru_string(tvb, offset, &slen);
  proto_tree_add_STR(tree, hf_uru_sdl_sdlname, tvb, offset,
		     slen, sdlname);
  /* freed later MAYBE_FREE(sdlname); */
  offset += slen;
  version = tvb_get_letohs(tvb, offset);
  proto_tree_add_item(tree, hf_uru_sdl_sdlversion, tvb, offset, 2, TRUE);
  offset += 2;
  if (!sdlname) {
    sdl = NULL;
  }
  else {
    sdl = get_sdl_info(sdlname, version);
  }
  if (!sdl) {
    offset = old_icky_heuristic_dissect_sdl(tvb, offset, tree,
					    sdlname, bufend);
  }
  else {
    offset = recursively_dissect_sdl(tvb, offset, tree, 1, sdl, bufend);
  }
  MAYBE_FREE(sdlname);

  return offset;
}

static gint
recursively_dissect_sdl(tvbuff_t *ntvb, gint noffset, proto_tree *tree,
			gint treect, struct sdl_info *sdl, gint bufend) {
  proto_item *tf, *ti, *tfk;
  proto_tree *sdl_tree, *sub_tree;
  guint8 flag8, varct, i, soffset, sdlflags;
  guint16 flag16;
  gboolean has_indices;
  char *str;
  guint slen;
  gint offseti, offsetk;
  guint32 subcount, k;

  flag16 = tvb_get_letohs(ntvb, noffset);
  tf = proto_tree_add_item(tree, hf_uru_sdl_eflag, ntvb, noffset, 2, TRUE);
  noffset += 2;
  flag8 = tvb_get_guint8(ntvb, noffset);
  tf = proto_tree_add_item(tree, hf_uru_sdl_unk6, ntvb, noffset, 1, TRUE);
  if (global_uru_hide_stuff && flag8 == 0x06) {
    PROTO_ITEM_SET_HIDDEN(tf);
  }
  noffset += 1;

  /* Here is special code to handle the broken brainStack in Ahnonay
     (which still exists in MOUL), because it can cause the dissector
     to lose track of the connection, if there are other messages following
     it in the same packet.
     In truth the dissector should do such length tests throughout, or as
     a simpler alternative, catch malformed packet exceptions itself at a
     level where it knows the message length already, so that dissection
     can continue unharmed after the malformed message. XXX */
  if (tvb_length_remaining(ntvb, noffset) < 2) {
    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, ntvb,
				       noffset-3, 3, 1,
				       "mangled brainStack");
    PROTO_ITEM_SET_GENERATED(tf);
    return noffset+tvb_length_remaining(ntvb, noffset);
  }

  varct = tvb_get_guint8(ntvb, noffset);
  proto_tree_add_item(tree, hf_uru_sdl_sdlct, ntvb, noffset, 1, TRUE);
  noffset += 1;
  if (varct < sdl->varct) {
    has_indices = TRUE;
  }
  else {
    has_indices = FALSE;
  }
  for (i = 0; i < varct; i++) {
    offseti = noffset;
    if (has_indices) {
      soffset = tvb_get_guint8(ntvb, noffset);
    }
    else {
      soffset = i;
    }
    if (soffset >= sdl->varct) {
      tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, ntvb,
					 noffset, 1, 1,
					 "SDL Variable Index too large");
      PROTO_ITEM_SET_GENERATED(tf);
      return noffset;
    }
    tf = proto_tree_add_none_format(tree, hf_uru_sdl_name, ntvb,
				    noffset, 0, "%s", sdl->vars[soffset].name);
    sdl_tree = proto_item_add_subtree(tf, ett_sdl_entry);
    if (has_indices) {
      proto_tree_add_item(sdl_tree, hf_uru_sdl_varidx, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
    }
    else {
      ti = proto_tree_add_uint(sdl_tree, hf_uru_sdl_varidx, ntvb,
			       noffset, 0, i);
      PROTO_ITEM_SET_GENERATED(ti);
    }

  /* According to Alcugs source:
     0x02 => next byte is zero, then there is an URUSTRING, then data
     !0x02 => next is data */

    ti = proto_tree_add_item(sdl_tree, hf_uru_sdl_tagflag, ntvb, noffset,
			     1, TRUE);
    if (global_uru_hide_stuff) {
      PROTO_ITEM_SET_HIDDEN(ti);
    }
    flag8 = tvb_get_guint8(ntvb, noffset);
    noffset += 1;
    if (flag8 == 0x02) {
      flag8 = tvb_get_guint8(ntvb, noffset);
      ti = proto_tree_add_item(sdl_tree, hf_uru_sdl_stbzero, ntvb, noffset,
			       1, TRUE);
      if (global_uru_hide_stuff && flag8 == 0) {
	PROTO_ITEM_SET_HIDDEN(ti);
      }
      noffset += 1;
      str = get_uru_string(ntvb, noffset, &slen);
      ti = proto_tree_add_STR(sdl_tree, hf_uru_sdl_tagstring, ntvb, noffset,
			      slen, str);
      if (global_uru_hide_stuff && slen == 2) {
	PROTO_ITEM_SET_HIDDEN(ti);
      }
      MAYBE_FREE(str);
      noffset += slen;
    }
    sdlflags = tvb_get_guint8(ntvb, noffset);
    proto_tree_add_item(sdl_tree, hf_uru_sdl_entryflags, ntvb, noffset,
			1, TRUE);
    noffset += 1;
    if (sdlflags & SDLFlagTimestamp) {
      add_uru_timestamp(ntvb, noffset, sdl_tree, hf_uru_sdl_timestamp,
			hf_uru_sdl_ts_sec, hf_uru_sdl_ts_usec);
      noffset += 8;
    }
    if (sdlflags & SDLFlagNoData) {
      gint where;
      where = noffset - 1;
      if (sdlflags & SDLFlagTimestamp) {
	where -= 8;
      }
      proto_tree_add_boolean_format(sdl_tree, hf_uru_sdl_val_default,
				    ntvb, where, 1, 1, "Default value");
      proto_item_set_len(tf, noffset-offseti);
      continue;
    }

    /* now we are at the data */
    if (sdl->vars[soffset].count) {
      subcount = sdl->vars[soffset].count;
      if (subcount != 1) {
	ti = proto_tree_add_uint(sdl_tree, hf_uru_sdl_arrct, ntvb, noffset, 
				 0, subcount);
	PROTO_ITEM_SET_GENERATED(ti);
      }
    }
    else {
      subcount = tvb_get_letohl(ntvb, noffset);
      proto_tree_add_item(sdl_tree, hf_uru_sdl_arrct, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
    }
    noffset = add_sdl_by_type(ntvb, noffset, sdl_tree,
			      sdl->vars[soffset].type, subcount, treect);

    proto_item_set_len(tf, noffset-offseti);
  } /* for i */

  varct = tvb_get_guint8(ntvb, noffset);
  proto_tree_add_item(tree, hf_uru_sdl_sdlsct, ntvb, noffset, 1, TRUE);
  noffset += 1;
  if (varct < sdl->structct) {
    has_indices = TRUE;
  }
  else {
    has_indices = FALSE;
  }
  for (i = 0; i < varct; i++) {
    offseti = noffset;
    if (has_indices) {
      soffset = tvb_get_guint8(ntvb, noffset);
    }
    else {
      soffset = i;
    }
    if (soffset >= sdl->structct) {
      tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, ntvb,
					 noffset, 1, 1,
					 "SDL Variable Index too large");
      PROTO_ITEM_SET_GENERATED(tf);
      return noffset;
    }
    tf = proto_tree_add_none_format(tree, hf_uru_sdl_name, ntvb,
				    noffset, 0, "%s",
				    sdl->structs[soffset].name);
    sdl_tree = proto_item_add_subtree(tf, ett_sdl_entry);
    if (has_indices) {
      proto_tree_add_item(sdl_tree, hf_uru_sdl_varidx, ntvb, noffset,
			  1, TRUE);
      noffset += 1;
    }
    else {
      ti = proto_tree_add_uint(sdl_tree, hf_uru_sdl_varidx, ntvb,
			       noffset, 0, i);
      PROTO_ITEM_SET_GENERATED(ti);
    }

  /* According to Alcugs source:
     0x02 => next byte is zero, then there is an URUSTRING, then data
     !0x02 => next is data */

    ti = proto_tree_add_item(sdl_tree, hf_uru_sdl_tagflag, ntvb, noffset,
			     1, TRUE);
    if (global_uru_hide_stuff) {
      PROTO_ITEM_SET_HIDDEN(ti);
    }
    flag8 = tvb_get_guint8(ntvb, noffset);
    noffset += 1;
    if (flag8 == 0x02) {
      flag8 = tvb_get_guint8(ntvb, noffset);
      ti = proto_tree_add_item(sdl_tree, hf_uru_sdl_stbzero, ntvb, noffset,
			       1, TRUE);
      if (global_uru_hide_stuff && flag8 == 0) {
	PROTO_ITEM_SET_HIDDEN(ti);
      }
      noffset += 1;
      str = get_uru_string(ntvb, noffset, &slen);
      ti = proto_tree_add_STR(sdl_tree, hf_uru_sdl_tagstring, ntvb, noffset,
			      slen, str);
      if (global_uru_hide_stuff && slen == 2) {
	PROTO_ITEM_SET_HIDDEN(ti);
      }
      MAYBE_FREE(str);
      noffset += slen;
    }
    sdlflags = tvb_get_guint8(ntvb, noffset);
    proto_tree_add_item(sdl_tree, hf_uru_sdl_entryflags, ntvb, noffset,
			1, TRUE);
    noffset += 1;
    if (sdlflags & SDLFlagTimestamp) {
      add_uru_timestamp(ntvb, noffset, sdl_tree, hf_uru_sdl_timestamp,
			hf_uru_sdl_ts_sec, hf_uru_sdl_ts_usec);
      noffset += 8;
    }
    if (sdlflags & SDLFlagNoData) {
      gint where;
      where = noffset - 1;
      if (sdlflags & SDLFlagTimestamp) {
	where -= 8;
      }
      proto_tree_add_boolean_format(sdl_tree, hf_uru_sdl_val_default,
				    ntvb, where, 1, 1, "Default value");
      proto_item_set_len(tf, noffset-offseti);
      continue;
    }

    /* now we are at the data */
    if (sdl->structs[soffset].count == 0) {
      subcount = tvb_get_letohl(ntvb, noffset);
      proto_tree_add_item(sdl_tree, hf_uru_sdl_sub_ct, ntvb, noffset,
			  4, TRUE);
      noffset += 4;
    }
    else {
      subcount = sdl->structs[soffset].count;
      ti = proto_tree_add_uint(sdl_tree, hf_uru_sdl_sub_ct, ntvb, noffset,
			       0, subcount);
      PROTO_ITEM_SET_GENERATED(ti);
    }
    proto_tree_add_item(sdl_tree, hf_uru_sdl_sub_unk, ntvb, noffset,
			1, TRUE);
    noffset += 1;
    for (k = 0; k < subcount; k++) {
      offsetk = noffset;
      tfk = proto_tree_add_none_format(sdl_tree, hf_uru_sdl_sub, ntvb,
				       noffset, 0, "%s #%u",
				       sdl->structs[soffset].name, k+1);
      sub_tree = proto_item_add_subtree(tfk, ett_sdl_subsdl);
      noffset = recursively_dissect_sdl(ntvb, noffset, sub_tree, treect + 1,
					sdl->structs[soffset].stype,
					bufend);
      proto_item_set_len(tfk, noffset-offsetk);
    }
    proto_item_set_len(tf, noffset-offseti);
  } /* for i */

  return noffset;
}

static gint
old_icky_heuristic_dissect_sdl(tvbuff_t *ntvb, gint noffset, proto_tree *tree,
			       char *sdlname, gint bufend) {
    proto_item *tf, *tfi;
    proto_tree *sdl_tree, *sub_tree;
    guint16 flag16;
    guint8 flag8, varct, soffset = 0, sdlflags;
    gint i /* must be signed */, len, datap /* must be signed */, treect = 1;
    gboolean has_indices, alcugs;
    gint structs, vars, offseti, offsetk;
    char *str;
    int sdltype = 0;

    flag16 = tvb_get_letohs(ntvb, noffset);
    tf = proto_tree_add_item(tree, hf_uru_sdl_eflag, ntvb, noffset, 2, TRUE);
    noffset += 2;
    flag8 = tvb_get_guint8(ntvb, noffset);
    tf = proto_tree_add_item(tree, hf_uru_sdl_unk6, ntvb, noffset, 1, TRUE);
    if (global_uru_hide_stuff && flag8 == 0x06) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    noffset += 1;

#if 0
    SDL names: AGMaster, physical, clothing, MorphSequence, <age name>,
      avatar, Sound, <object name>, Layer
      Live: avatarPhysical
#endif
#define IS_AVATAR 0x1
#define IS_PHYSICAL 0x2
#define IS_CLOTHING 0x4
#define IS_MORPH 0x8
#define IS_AGMASTER 0x10
#define IS_SOUND 0x20
#define IS_LAYER 0x40
#define IS_AVPHYS 0x80
    vars = -1;
    structs = 0;
    if (sdlname) {
      if (!strcmp(sdlname, "clothing")) {
	vars = 1;
	structs = 2;
	sdltype = IS_CLOTHING;
      }
      else if (!strcmp(sdlname, "avatar")) {
	vars = 1;
	structs = 1;
	sdltype = IS_AVATAR;
      }
      else if (!strcmp(sdlname, "MorphSequence")) {
	vars = 1;
	structs = 1;
	sdltype = IS_MORPH;
      }
      else if (!strcmp(sdlname, "physical")) {
	vars = 5;
	structs = 0;
	sdltype = IS_PHYSICAL;
      }
      else if (!strcmp(sdlname, "AGMaster")) {
	vars = 1;
	structs = 1;
	sdltype = IS_AGMASTER;
      }
      else if (!strcmp(sdlname, "Sound")) {
	vars = 0;
	structs = 1;
	sdltype = IS_SOUND;
      }
      else if (!strcmp(sdlname, "Layer")) {
	vars = 3;
	structs = 1;
	sdltype = IS_LAYER;
      }
      else if (!strcmp(sdlname, "avatarPhysical")) { /* Live */
	vars = 3;
	structs = 0;
	sdltype = IS_AVPHYS;
      }
    }

    /* iterate through values */
    varct = tvb_get_guint8(ntvb, noffset);
    proto_tree_add_item(tree, hf_uru_sdl_sdlct, ntvb, noffset, 1, TRUE);
    noffset += 1;
    has_indices = FALSE;
    if (varct > 0) {
      soffset = tvb_get_guint8(ntvb, noffset);
      if (soffset != 0x02) {
	soffset = tvb_get_guint8(ntvb, noffset+1);
	if (soffset == 0x02) {
	  /* Could be Alcugs though! But I'll notice soon enough. */
	  has_indices = TRUE;
	}
      }
      else {
	soffset = tvb_get_guint8(ntvb, noffset+1);
	if (soffset == 0x02) {
	  has_indices = TRUE;
	}
      }
    }
    for (i = 0; i < varct; i++) {
      offseti = noffset;
      if (has_indices) {
	soffset = tvb_get_guint8(ntvb, noffset);
      }
      tfi = proto_tree_add_none_format(tree, hf_uru_sdl_name, ntvb, noffset,
				       0, "Name unknown, index %u",
				       has_indices ? soffset : i);
      sdl_tree = proto_item_add_subtree(tfi, ett_sdl_entry);
      if (has_indices) {
	proto_tree_add_item(sdl_tree, hf_uru_sdl_varidx, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
      }
      else {
	tf = proto_tree_add_uint(sdl_tree, hf_uru_sdl_varidx, ntvb,
				 noffset, 0, i);
	PROTO_ITEM_SET_GENERATED(tf);
      }
      datap = get_sdl_record(ntvb, noffset, sdl_tree, bufend, -1,
			     &sdlflags, &len, &alcugs);
      if (datap < 0) {
	/* there was a problem parsing */
	proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
				      ntvb, noffset, bufend-noffset, 1,
				      "Can't parse SDL record here");
	noffset = bufend;
	return noffset;
      }
      else if (alcugs && varct > 1) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, datap, len, 1,
				      "Alcugs server? All bets are off.");
	PROTO_ITEM_SET_GENERATED(tf);
	noffset = datap+len;
	return noffset;
      }
      else if (sdlflags & SDLFlagNoData) {
	noffset = datap;
      }
      else {
	noffset = datap; /* front stuff already handled */

#ifdef DEBUG_SDL
	proto_tree_add_text(tree, ntvb, noffset, 0, "here: indices: %d varct: %d len: %d i=%d", has_indices, varct, len, i);
#endif
	if (has_indices || i+1 == varct) {
	  len--;
	}
	if (sdltype == IS_PHYSICAL) {
	  gint newlen = -1, index;
	  if (has_indices) {
	    index = soffset;
	  }
	  else {
	    index = i;
	  }
	  if (index == 4) {
	    newlen = dissect_uru_object_subtree(ntvb, noffset, sdl_tree,
						ETT_ODESC(treect), NULL,
						FALSE, NULL, NULL, NULL,
						-1, 1, hf_uru_sdl_phys_mgr);
	    treect++;
	  }
	  else if (index == 0 || index == 2 || index == 3) {
	    gfloat x, y, z;
	    newlen = noffset;
	    x = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_x, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    y = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_y, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    z = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_z, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    if (index == 0) {
	      proto_tree_add_none_format(sdl_tree, hf_uru_sdl_val_3tuple, ntvb,
					 noffset, 12,
					 "Location: %f %f %f", x, y, z);
	    }
	    else if (index == 2) {
	      proto_tree_add_none_format(sdl_tree, hf_uru_sdl_val_3tuple, ntvb,
					 noffset, 12,
					 "Linear: [%f %f %f]", x, y, z);
	    }
	    else {
	      proto_tree_add_none_format(sdl_tree, hf_uru_sdl_val_3tuple, ntvb,
					 noffset, 12,
					 "Angular: [%f %f %f]", x, y, z);
	    }
	  }
	  else if (index == 1) {
	    gfloat a, b, c, d;
	    newlen = noffset;
	    a = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_qa, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    b = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_qb, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    c = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_qc, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    d = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_qd, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    proto_tree_add_none_format(sdl_tree, hf_uru_sdl_val_quat, ntvb,
				       noffset, 16,
				       "Quaternion: %f %f %f %f", a, b, c, d);
	  }
	  else {
	    /* shouldn't really happen */
	    add_record_guess(ntvb, noffset, sdl_tree, len);
	    newlen = noffset+len;
	  }
	  if (newlen >= 0 && newlen-noffset != len) {
	    tf = proto_tree_add_boolean_format(sdl_tree,
					  hf_uru_dissection_error,
					  ntvb, noffset, len, 1,
					  "Lengths don't match, actual: %u",
					  newlen-noffset);
	    PROTO_ITEM_SET_GENERATED(tf);
	  }
	  noffset += len;
	} /* if sdltype == IS_PHYSICAL */
	else if (sdltype == IS_AVPHYS) {
	  gint newlen = noffset;

	  if (i == 0) {
	    gfloat x, y, z;
	    x = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_x, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    y = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_y, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    z = tvb_get_letohieee_float(ntvb, newlen);
	    tf = proto_tree_add_item(sdl_tree, hf_uru_sdl_val_z, ntvb, newlen,
				     4, TRUE);
	    PROTO_ITEM_SET_HIDDEN(tf);
	    newlen += 4;
	    proto_tree_add_none_format(sdl_tree, hf_uru_sdl_val_3tuple, ntvb,
				       newlen, 12,
				       "Location: %f %f %f", x, y, z);
	  }
	  else {
	    /* XXX */
	    add_record_guess(ntvb, noffset, sdl_tree, len);
	    newlen = noffset + len;
	  }
	  if (newlen >= 0 && newlen-noffset != len) {
	    tf = proto_tree_add_boolean_format(sdl_tree,
					  hf_uru_dissection_error,
					  ntvb, noffset, len, 1,
					  "Lengths don't match, actual: %u",
					  newlen-noffset);
	    PROTO_ITEM_SET_GENERATED(tf);
	  }
	  noffset += len;
	} /* if sdltype == IS_AVPHYS */
	else if (sdltype == IS_CLOTHING) {
	  gint toff;
	  toff = dissect_uru_object_subtree(ntvb, noffset, sdl_tree,
					    ETT_ODESC(treect), NULL,
					    FALSE, NULL, NULL, NULL,
					    -1, 1, hf_uru_sdl_cl_linkeff);
	  treect++;
	  if (toff-noffset != len) {
	    tf = proto_tree_add_boolean_format(sdl_tree,
					  hf_uru_dissection_error,
					  ntvb, toff, len, 1,
					  "Lengths don't match, actual: %u",
					  toff-noffset);
	    PROTO_ITEM_SET_GENERATED(tf);
	  }
	  noffset += len;
	} /* if sdltype == IS_CLOTHING */
	else if (sdltype & (IS_MORPH|IS_AVATAR|IS_LAYER|IS_AGMASTER)) {
	  if (len >= 4) {
	    add_record_array(ntvb, noffset, sdl_tree, len);
	    noffset += len;
	  }
	  else {
	    add_record_guess(ntvb, noffset, sdl_tree, len);
	    noffset += len;
	  }
	}
	else {
	  add_record_guess(ntvb, noffset, sdl_tree, len);
	  noffset += len;
	}
      }
      proto_item_set_len(tfi, noffset-offseti);
    } /* for i */
    varct = tvb_get_guint8(ntvb, noffset);
    proto_tree_add_item(tree, hf_uru_sdl_sdlsct, ntvb, noffset, 1, TRUE);
    noffset += 1;
    if (varct < structs) {
      has_indices = TRUE;
    }
    else {
      has_indices = FALSE;
      soffset = 0;
    }
    for (i = 0; i < varct; i++) {
      offseti = noffset;
      if (has_indices) {
	soffset = tvb_get_guint8(ntvb, noffset);
      }
      tfi = proto_tree_add_none_format(tree, hf_uru_sdl_name, ntvb, noffset,
				       0, "Name unknown, index %u",
				       has_indices ? soffset : i);
      sdl_tree = proto_item_add_subtree(tfi, ett_sdl_entry);
      if (has_indices) {
	proto_tree_add_item(sdl_tree, hf_uru_sdl_varidx, ntvb, noffset,
			    1, TRUE);
	noffset += 1;
      }
      else {
	tf = proto_tree_add_uint(sdl_tree, hf_uru_sdl_varidx, ntvb,
				 noffset, 0, i);
	PROTO_ITEM_SET_GENERATED(tf);
      }
      datap = get_sdl_record(ntvb, noffset, sdl_tree, bufend, -1,
			     &sdlflags, &len, &alcugs);
      if (datap < 0) {
	/* there was a problem parsing */
	proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
				      ntvb, noffset, bufend-noffset, 1,
				      "Can't parse SDL record here");
	noffset = bufend;
	return noffset;
      }
      else if (alcugs && varct > 1) {
	tf = proto_tree_add_boolean_format(tree, hf_uru_incomplete_dissection,
				      ntvb, datap, len, 1,
				      "Alcugs server? All bets are off.");
	PROTO_ITEM_SET_GENERATED(tf);
	noffset = datap+len;
	return noffset;
      }
      else if (sdlflags & SDLFlagNoData) {
	noffset = datap;
      }
      else {
	guint32 subcount, k, l;
	guint8 subvarct;
	proto_item *tfk, *tfl;
	proto_tree *tree_l;
	int offsetl;

	noffset = datap; /* front stuff already handled */

	if ((sdltype == IS_CLOTHING && ((has_indices ? soffset : i) == 1))
	    || (sdltype == IS_LAYER)) {
	  subcount = 1;
	}
	else {
	  subcount = tvb_get_letohl(ntvb, noffset);
	  proto_tree_add_item(sdl_tree, hf_uru_sdl_sub_ct, ntvb, noffset,
			      4, TRUE);
	  noffset += 4;
	}
	proto_tree_add_item(sdl_tree, hf_uru_sdl_sub_unk, ntvb, noffset,
			    1, TRUE);
	noffset += 1;

	for (k = 0; k < subcount; k++) {
	  offsetk = noffset;
	  tfk = proto_tree_add_none_format(sdl_tree, hf_uru_sdl_sub, ntvb,
					   noffset, 0, "(unknown) #%u", k+1);
	  sub_tree = proto_item_add_subtree(tfk, ett_sdl_subsdl);
	  proto_tree_add_item(sub_tree, hf_uru_sdl_eflag, ntvb, noffset,
			      2, TRUE);
	  noffset += 2;
	  flag8 = tvb_get_guint8(ntvb, noffset);
	  tf = proto_tree_add_item(sub_tree, hf_uru_sdl_unk6, ntvb, noffset,
				   1, TRUE);
	  if (global_uru_hide_stuff && flag8 == 0x06) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	  noffset += 1;

	  subvarct = tvb_get_guint8(ntvb, noffset);
	  proto_tree_add_item(sub_tree, hf_uru_sdl_sdlct, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;

	  for (l = 0; l < subvarct; l++) {
	    offsetl = noffset;
	    tfl = proto_tree_add_none_format(sub_tree, hf_uru_sdl_name, ntvb,
					     noffset, 0,
					     "Name unknown, index %u", l);
	    tree_l = proto_item_add_subtree(tfl, ett_sdl_entry);
	    tf = proto_tree_add_uint(sub_tree, hf_uru_sdl_varidx, ntvb,
				     noffset, 0, l);
	    PROTO_ITEM_SET_GENERATED(tf);
	    datap = get_sdl_record(ntvb, noffset, tree_l, bufend, -1,
				   &sdlflags, &len, &alcugs);
	    if (datap < 0) {
	      /* there was a problem parsing */
	      proto_tree_add_boolean_format(tree,
					hf_uru_dissection_error,
					ntvb, noffset, bufend-noffset, 1,
					"Can't parse SDL record here");
	      noffset = bufend;
	      return noffset;
	    }
	    else if (alcugs) {
	      tf = proto_tree_add_boolean_format(tree,
					    hf_uru_incomplete_dissection,
					    ntvb, datap, len, 1,
					    "Help! Misdetected as Alcugs");
	      PROTO_ITEM_SET_GENERATED(tf);
	      noffset = datap+len;
	      return noffset;
	    }
	    else if (sdlflags & SDLFlagNoData) {
	      noffset = datap;
	    }
	    else {
	      noffset = datap; /* front stuff already handled */

#ifdef DEBUG_SDL
	      proto_tree_add_text(tree, ntvb, noffset, 0, "here2: indices: %d varct: %d len: %d subcount: %d subvarct: %d i=%d k=%d l=%d", has_indices, varct, len, subcount, subvarct, i, k, l);
#endif
	      if (/*sub_has_indices*/0 && l+1 < subvarct) {
		len--; /* next index */
	      }
	      else if (l+1 == subvarct) {
		len--; /* struct count */
		if (k+1 < subcount) {
		  len -= 4; /* for next flags & var count */
		}
		else if (has_indices && i+1 < varct) {
		  len--;
		}
	      }

	      if (sdltype == IS_CLOTHING
		  && ((has_indices ? soffset : i) == 0)) {
		gint off;
		off = noffset;
		if (l == 0) {
		  noffset = dissect_uru_object_subtree(ntvb, noffset, tree_l,
						       -1, &str,
						       FALSE, NULL, NULL, NULL,
						       -1, 1, -1);
		  proto_tree_add_STR(tree_l, hf_uru_sdl_cl_item,
				     ntvb, off, noffset-off, str);
		  MAYBE_FREE(str);
		}
		else {
		  guint8 r, g, b;
		  r = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_r,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  g = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_g,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  b = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_b,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  proto_tree_add_none_format(tree_l, hf_uru_sdl_val_clr,
					ntvb, off, noffset-off,
					"Color %d: %3u %3u %3u (%f %f %f)",
					l, r, g, b, r/255.0, g/255.0, b/255.0);
		}
	      }
	      else if (sdltype == IS_CLOTHING) {
		if (l == 0) {
		  gint off;
		  guint8 r, g, b;
		  off = noffset;
		  r = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_r,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  g = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_g,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  b = tvb_get_guint8(ntvb, noffset);
		  tf = proto_tree_add_item(tree_l, hf_uru_sdl_val_b,
					   ntvb, noffset, 1, TRUE);
		  PROTO_ITEM_SET_HIDDEN(tf);
		  noffset += 1;
		  proto_tree_add_none_format(tree_l, hf_uru_sdl_val_clr,
					ntvb, off, noffset-off,
					"Color: %3u %3u %3u (%f %f %f)",
					r, g, b, r/255.0, g/255.0, b/255.0);
		}
		else {
		  add_record_array(ntvb, noffset, tree_l, len);
		  noffset += len;
		}
	      }
	      else if (sdltype == IS_MORPH) {
		if (l == 0) {
		  noffset = dissect_uru_object_subtree(ntvb, noffset, tree_l,
						       ETT_ODESC(treect), NULL,
						       FALSE, NULL, NULL, NULL,
						       -1, 1, hf_uru_sdl_morph);
		  treect++;
		}
		else {
		  add_record_array(ntvb, noffset, tree_l, len);
		  noffset += len;
		}
	      }
	      else {
		add_record_guess(ntvb, noffset, tree_l, len);
		noffset += len;
	      }
	    }
	    proto_item_set_len(tfl, noffset-offsetl);
	  } /* for l */

	  subvarct = tvb_get_guint8(ntvb, noffset);
	  proto_tree_add_item(sub_tree, hf_uru_sdl_sdlsct, ntvb, noffset,
			      1, TRUE);
	  noffset += 1;

	  /* this can recurse forever in theory, but in practice only
	     avatar messages go this deep */
	  if (subvarct > 0 && sdltype != IS_AVATAR) {
	    tf = proto_tree_add_boolean_format(tree,
					  hf_uru_incomplete_dissection,
					  ntvb, noffset, bufend-noffset, 1,
					  "Recursion too deep");
	    PROTO_ITEM_SET_GENERATED(tf);
	    noffset = bufend;
	    return noffset;
	  }
	  for (l = 0; l < subvarct; l++) {
	    guint32 avct, m, n;
	    guint8 avvarct;
	    proto_item *tfm, *tfn;
	    proto_tree *tree_m, *tree_n;
	    gint offsetm, offsetn;

	    offsetl = noffset;
	    tfl = proto_tree_add_none_format(sub_tree, hf_uru_sdl_name, ntvb,
					     noffset, 0,
					     "Name unknown, index %u", l);
	    tf = proto_tree_add_uint(sub_tree, hf_uru_sdl_varidx, ntvb,
				     noffset, 0, l);
	    PROTO_ITEM_SET_GENERATED(tf);
	    tree_l = proto_item_add_subtree(tfl, ett_sdl_entry);
	    datap = get_sdl_record(ntvb, noffset, tree_l, bufend, -1,
				   &sdlflags, &len, &alcugs);
	    if (datap < 0) {
	      /* there was a problem parsing */
	      proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					    ntvb, noffset, bufend-noffset, 1,
					    "Can't parse SDL record here");
	      noffset = bufend;
	      return noffset;
	    }
	    else if (alcugs) {
	      tf = proto_tree_add_boolean_format(tree,
					    hf_uru_incomplete_dissection,
					    ntvb, datap, len, 1,
					    "Help! Misdetected as Alcugs");
	      PROTO_ITEM_SET_GENERATED(tf);
	      noffset = datap+len;
	      return noffset;
	    }
	    else if (sdlflags & SDLFlagNoData) {
	      noffset = datap;
	    }
	    else {
	      noffset = datap; /* front stuff already handled */

	      avct = tvb_get_letohl(ntvb, noffset);
	      proto_tree_add_item(tree_l, hf_uru_sdl_sub_ct, ntvb, noffset,
				  4, TRUE);
	      noffset += 4;
	      proto_tree_add_item(tree_l, hf_uru_sdl_sub_unk, ntvb, noffset,
				  1, TRUE);
	      noffset += 1;
	      for (m = 0; m < avct; m++) {
		offsetm = noffset;
		tfm = proto_tree_add_none_format(tree_l, hf_uru_sdl_sub,
						 ntvb, noffset, 0,
						 "(unknown) #%u", m+1);
		tree_m = proto_item_add_subtree(tfm, ett_sdl_subsdl);
		proto_tree_add_item(tree_m, hf_uru_sdl_eflag, ntvb, noffset,
				    2, TRUE);
		noffset += 2;
		flag8 = tvb_get_guint8(ntvb, noffset);
		tf = proto_tree_add_item(tree_m, hf_uru_sdl_unk6, ntvb,
					 noffset, 1, TRUE);
		if (global_uru_hide_stuff && flag8 == 0x06) {
		  PROTO_ITEM_SET_HIDDEN(tf);
		}
		noffset += 1;

		avvarct = tvb_get_guint8(ntvb, noffset);
		proto_tree_add_item(tree_m, hf_uru_sdl_sdlct, ntvb, noffset,
				    1, TRUE);
		noffset += 1;
		for (n = 0; n < avvarct; n++) {
		  guint8 av_soffset;

		  offsetn = noffset;
		  av_soffset = tvb_get_guint8(ntvb, noffset);
		  tfn = proto_tree_add_none_format(tree_m,
					hf_uru_sdl_name, ntvb, noffset, 0,
					"Name unknown, index %u", av_soffset);
		  tree_n = proto_item_add_subtree(tfn, ett_sdl_entry);
		  proto_tree_add_item(tree_n, hf_uru_sdl_varidx, ntvb,
				      noffset, 1, TRUE);
		  noffset += 1;
		  datap = get_sdl_record(ntvb, noffset, tree_n,
					 bufend, -1, &sdlflags, &len, &alcugs);
		  if (datap < 0) {
		    /* there was a problem parsing */
		    proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					ntvb, noffset, bufend-noffset, 1,
					"Can't parse SDL record here");
		    noffset = bufend;
		    return noffset;
		  }
		  else if (alcugs) {
		    tf = proto_tree_add_boolean_format(tree,
					hf_uru_incomplete_dissection,
					ntvb, datap, len, 1,
					"Help! Misdetected as Alcugs");
		    PROTO_ITEM_SET_GENERATED(tf);
		    noffset = datap+len;
		    return noffset;
		  }
		  else if (sdlflags & SDLFlagNoData) {
		    noffset = datap;
		  }
		  else {
		    noffset = datap; /* front stuff already handled */

#ifdef DEBUG_SDL
		    proto_tree_add_text(tree, ntvb, noffset, 0, "here3: indices: %d varct: %d len: %d subcount: %d subvarct: %d avct: %d avvarct: %d i=%d k=%d l=%d m=%d n=%d", has_indices, varct, len, subcount, subvarct, avct, avvarct, i, k, l, m, n);
#endif
		    if (/*av_has_indices*/1 && n+1 < avvarct) {
		      len--; /* next index */
		    }
		    else if (n+1 == avvarct) {
		      len--; /* struct count */
		      if (m+1 < avct) {
			len -= 5; /* for next flags & 2 counts */
		      }
		      else if (/*sub_has_indices*/0 && l+1 < subvarct) {
			len--; /* next index */
		      }
		      else if (l+1 == subvarct) {
			/* no struct count */
			if (k+1 < subcount) {
			  len -= 4; /* for next flags & var count */
			}
			else if (has_indices && i+1 < varct) {
			  len--;
			}
			else if (i+1 == varct) {
			  /* no struct count */
			}
		      }
		    }

		    if (av_soffset == 3 && len > 1) {
		      noffset = dissect_uru_object_subtree(ntvb, noffset,
						tree_n, ETT_ODESC(treect),
						NULL, FALSE, NULL, NULL, NULL,
						-1, 1, hf_uru_sdl_val_obj);
		      treect++;
		    }
		    else {
		      add_record_guess(ntvb, noffset, tree_n, len);
		      noffset += len;
		    }
		  }
		  proto_item_set_len(tfn, noffset-offsetn);
		} /* for n */

		avvarct = tvb_get_guint8(ntvb, noffset);
		proto_tree_add_item(tree_m, hf_uru_sdl_sdlsct, ntvb, noffset,
				    1, TRUE);
		noffset += 1;
		for (n = 0; n < avvarct; n++) {
		  guint32 stagect, o, p;
		  guint8 stagevarct;

		  offsetn = noffset;
		  tfn = proto_tree_add_none_format(tree_m,
					hf_uru_sdl_name, ntvb, noffset, 0,
					"Name unknown, index %u", n);
		  tf = proto_tree_add_uint(sub_tree, hf_uru_sdl_varidx, ntvb,
					   noffset, 0, n);
		  PROTO_ITEM_SET_GENERATED(tf);
		  tree_n = proto_item_add_subtree(tfn, ett_sdl_entry);
		  datap = get_sdl_record(ntvb, noffset, tree_n,
					 bufend, -1, &sdlflags, &len, &alcugs);
		  if (datap < 0) {
		    /* there was a problem parsing */
		    proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					ntvb, noffset, bufend-noffset, 1,
					"Can't parse SDL record here");
		    noffset = bufend;
		    return noffset;
		  }
		  else if (alcugs) {
		    tf = proto_tree_add_boolean_format(tree,
					hf_uru_incomplete_dissection,
					ntvb, datap, len, 1,
					"Help! Misdetected as Alcugs");
		    PROTO_ITEM_SET_GENERATED(tf);
		    noffset = datap+len;
		    return noffset;
		  }
		  else if (sdlflags & SDLFlagNoData) {
		    noffset = datap;
		  }
		  else {
		    noffset = datap; /* front stuff already handled */

		    stagect = tvb_get_letohl(ntvb, noffset);
		    proto_tree_add_item(tree_n, hf_uru_sdl_sub_ct, ntvb,
					noffset, 4, TRUE);
		    noffset += 4;
		    proto_tree_add_item(tree_n, hf_uru_sdl_sub_unk, ntvb,
					noffset, 1, TRUE);
		    noffset += 1;
		    for (o = 0; o < stagect; o++) {
		      proto_item *tfo, *tfp;
		      proto_tree *tree_o, *tree_p;
		      gint offseto, offsetp;

		      offseto = noffset;
		      tfo = proto_tree_add_none_format(tree_n, hf_uru_sdl_sub,
						       ntvb, noffset, 0,
						       "(unknown) #%u", o+1);
		      tree_o = proto_item_add_subtree(tfo, ett_sdl_subsdl);
		      proto_tree_add_item(tree_o, hf_uru_sdl_eflag, ntvb,
					  noffset, 2, TRUE);
		      noffset += 2;
		      flag8 = tvb_get_guint8(ntvb, noffset);
		      tf = proto_tree_add_item(tree_o, hf_uru_sdl_unk6,
					       ntvb, noffset, 1, TRUE);
		      if (global_uru_hide_stuff && flag8 == 0x06) {
			PROTO_ITEM_SET_HIDDEN(tf);
		      }
		      noffset += 1;

		      stagevarct = tvb_get_guint8(ntvb, noffset);
		      proto_tree_add_item(tree_o, hf_uru_sdl_sdlct, ntvb,
					  noffset, 1, TRUE);
		      noffset += 1;
		      for (p = 0; p < stagevarct; p++) {
			offsetp = noffset;
			flag8 = tvb_get_guint8(ntvb, noffset);
			tfp = proto_tree_add_none_format(tree_o,
					hf_uru_sdl_name, ntvb, noffset, 0,
					"Name unknown, index %u", flag8);
			tree_p = proto_item_add_subtree(tfp, ett_sdl_entry);
			proto_tree_add_item(tree_p, hf_uru_sdl_varidx,
					    ntvb, noffset, 1, TRUE);
			noffset += 1;
			datap = get_sdl_record(ntvb, noffset, tree_p,
					       bufend, -1,
					       &sdlflags, &len, &alcugs);
			if (datap < 0) {
			  /* there was a problem parsing */
			  proto_tree_add_boolean_format(tree,
					hf_uru_dissection_error,
					ntvb, noffset, bufend-noffset, 1,
					"Can't parse SDL record here");
			  noffset = bufend;
			  return noffset;
			}
			else if (alcugs) {
			  tf = proto_tree_add_boolean_format(tree,
					hf_uru_incomplete_dissection,
					ntvb, datap, len, 1,
					"Help! Misdetected as Alcugs");
			  PROTO_ITEM_SET_GENERATED(tf);
			  noffset = datap+len;
			  return noffset;
			}
			else if (sdlflags & SDLFlagNoData) {
			  noffset = datap;
			}
			else {
			  noffset = datap; /* front stuff already handled */
			  
#ifdef DEBUG_SDL
			  proto_tree_add_text(tree, ntvb, noffset, 0, "here4: indices: %d varct: %d len: %d subcount: %d subvarct: %d avct: %d avvarct: %d stagect: %d stagevarct: %d i=%d k=%d l=%d m=%d n=%d o=%d p=%d", has_indices, varct, len, subcount, subvarct, avct, avvarct, stagect, stagevarct, i, k, l, m, n, o, p);
#endif
			  if (/*stage_has_indices*/1 && p+1 < stagevarct) {
			    len--; /* next index */
			  }
			  else if (p+1 == stagevarct) {
			    len--; /* struct count */
			    if (o+1 < stagect) {
			      len -= 5; /* for next flags & 2 counts */
			    }
			    else if (/*av_has_indices*/1 && n+1 < avvarct) {
			      len--; /* next index */
			    }
			    else if (n+1 == avvarct) {
			      /* no struct count */
			      if (m+1 < avct) {
				len -= 5; /* for next flags & 2 counts */
			      }
			      else if (/*sub_has_indices*/0 && l+1 < subvarct) {
				len--; /* next index */
			      }
			      else if (l+1 == subvarct) {
				/* no struct count */
				if (k+1 < subcount) {
				  len -= 4; /* for next flags & var count */
				}
				else if (has_indices && i+1 < varct) {
				  len--;
				}
				else if (i+1 == varct) {
				  /* no struct count */
				}
			      }
			    }
			  }

			  add_record_guess(ntvb, noffset, tree_p, len);
			  noffset += len;
			}
			proto_item_set_len(tfp, noffset-offsetp);
		      } /* for p */

		      stagevarct = tvb_get_guint8(ntvb, noffset);
		      proto_tree_add_item(tree_o, hf_uru_sdl_sdlsct, ntvb,
					  noffset, 1, TRUE);
		      noffset += 1;
		      if (stagevarct != 0) {
			proto_tree_add_boolean_format(tree,
					hf_uru_incomplete_dissection,
					ntvb, noffset,
					tvb_length_remaining(ntvb, noffset),
					1, "Recursion too deep");
			noffset = bufend;
			return noffset;
		      }
		      proto_item_set_len(tfo, noffset-offseto);
		    } /* for o */
		  }
		  proto_item_set_len(tfn, noffset-offsetn);
		} /* for n */
		proto_item_set_len(tfm, noffset-offsetm);
	      } /* for m */
	    }
	    proto_item_set_len(tfl, noffset-offsetl);
	  } /* for l */
	  proto_item_set_len(tfk, noffset-offsetk);
	} /* for k */
      }
      proto_item_set_len(tfi, noffset-offseti);
    } /* for i */

    return noffset;
}

/********** end of dissectors **********/

#ifdef EPHEMERAL_BUFS
/* do NOT free returned pointers */
#else
/* if a non-NULL value is returned, it must be freed */
#endif
static char *
get_uru_string(tvbuff_t *tvb, gint offset, guint *len)
{
  char *string;
  guint16 strinfo, length;
  guint8 flipped;

  strinfo = tvb_get_letohs(tvb, offset);
  length = strinfo & 0x0FFF;
  flipped = (strinfo & 0xF000) >> 8;
  *len = length+2;
  if (length == 0) {
    return NULL;
  }
#ifdef EPHEMERAL_BUFS
  string = tvb_get_ephemeral_string(tvb, offset+2, length);
#else
  string = (char*)tvb_get_string(tvb, offset+2, length);
#endif
  if (flipped) {
    int i;
    for (i = 0; i < length; i++) {
      string[i] = ~string[i];
    }
  }
  return string;
}

static char *
get_uru_hexstring(tvbuff_t *tvb, gint offset, guint *len)
{
  guint reallen, i;
  char *string, *hexstring;

  string = get_uru_string(tvb, offset, &reallen);
  reallen -= 2;
  *len = (reallen*2)+2;
  if (reallen == 0) {
    return NULL;
  }
#ifdef EPHEMERAL_BUFS
  hexstring = ep_alloc((reallen*2)+1);
#else
  hexstring = g_malloc((reallen*2)+1);
#endif
  for (i = 0; i < reallen; i++) {
    g_snprintf(hexstring+(i*2), 3, "%02X", (guint8)string[i]);
  }
  hexstring[i*2] = '\0';
#ifndef EPHEMERAL_BUFS
  g_free(string);
#endif
  return hexstring;
}

static void
add_uru_timestamp(tvbuff_t *tvb, gint offset, proto_tree *tree,
		  int hf_ts, int hf_sec, int hf_usec) {
  proto_item *ti, *tf;
  guint32 time[2];
  /*proto_tree_add_item(uru_tree, hf_ts, tvb, offset, 8, TRUE);*/
  /* because the above with FT_RELATIVE_TIMESTAMP doesn't work
     (nice of them to say it can be done)... and that expects
     sec.nanoseconds anyway */
  time[0] = tvb_get_letohl(tvb, offset);
  time[1] = tvb_get_letohl(tvb, offset+4);
  ti = proto_tree_add_bytes_format_value(tree, hf_ts, tvb, offset, 8,
					 (guint8*)time, "%u.%06u",
					 time[0], time[1]);

  /* for packet filters */
  tf = proto_tree_add_item(tree, hf_sec, tvb, offset, 4, TRUE);
  PROTO_ITEM_SET_HIDDEN(tf);
  tf = proto_tree_add_item(tree, hf_usec, tvb, offset+4, 4, TRUE);
  PROTO_ITEM_SET_HIDDEN(tf);
  /* bonus info */
  if (time[0] > 1000000000) { /* Sun Sep  9 01:46:40 2001 GMT */
    append_ts_formatted(ti, time[0], time[1], TRUE);
  }
}

static void
append_ts_formatted(proto_item *ti, guint32 sec, guint32 usec,
		    gboolean include_usec) {
  /* code from epan/column-utils.c */
  struct tm *tmp;
  time_t then;

  then = sec;
  tmp = localtime(&then);
  if (tmp != NULL) {
    /* while it would be nice to do all the time formats and all the
       precisions, it just doesn't seem worth the trouble to me */
    if (timestamp_get_type() == TS_ABSOLUTE_WITH_DATE) {
      if (include_usec) {
	proto_item_append_text(ti, " (%04d-%02d-%02d %02d:%02d:%02d.%06ld)",
			       tmp->tm_year + 1900,
			       tmp->tm_mon + 1,
			       tmp->tm_mday,
			       tmp->tm_hour,
			       tmp->tm_min,
			       tmp->tm_sec,
			       (long)usec);
      }
      else {
	proto_item_append_text(ti, " (%04d-%02d-%02d %02d:%02d:%02d)",
			       tmp->tm_year + 1900,
			       tmp->tm_mon + 1,
			       tmp->tm_mday,
			       tmp->tm_hour,
			       tmp->tm_min,
			       tmp->tm_sec);
      }
    }
    else {
      if (include_usec) {
	proto_item_append_text(ti, " (%02d:%02d:%02d.%06ld)",
			       tmp->tm_hour,
			       tmp->tm_min,
			       tmp->tm_sec,
			       (long)usec);
      }
      else {
	proto_item_append_text(ti, " (%02d:%02d:%02d)",
			       tmp->tm_hour,
			       tmp->tm_min,
			       tmp->tm_sec);
      }
    }
  }
}

/*
 * This is the one-size-fits-all URUOBJECTREF/URUOBJECTDESC parser.  All
 * parsing of these types should be done here; insane as it looks, add more
 * arguments if you need more fields exported.
 *
 * If ett is >= 0, a full subtree is populated, using the hf_*
 *   field values. If which_hf is 0, hf_uru_obj_* are used and if which_hf is
 *   1, hf_uru_subobj_* are used. hf_obj is the field that will be used for
 *   the subtree and it should be of type FT_NONE.
 * Set is_ref to TRUE if it's an URUOBJECTREF; *exists will be filled in
 *   if it is not NULL. The proto field hf_exists will be set.
 * If summary is not NULL, it is set to a string representation of the object.
 * If objtype or name is NULL, it's not filled in; if non-null it is.
#ifdef EPHEMERAL_BUFS
 * Do NOT free *name or *summary.
#else
 * If not NULL, *name and *summary MUST be freed.
#endif
 *
 * To help detect dissector bugs, set hf_obj and hf_exists to -1 if they are
 * not expected to be used. (When ett < 0 and is_ref is FALSE, respectively.)
 */
static gint
dissect_uru_object_subtree(tvbuff_t *tvb, gint offset, proto_tree *tree,
			   int ett, char **summary,
			   gboolean is_ref, guint8 *exists,
			   guint16 *objtype, char **name,
			   int hf_exists, int which_hf, int hf_obj)
{
  proto_item *ti, *tf;
  proto_tree *sub_tree = NULL;
  guint off, sumlen, s;
  /* parts of the descriptor */
  guint8 flags, ex = 0, unk = 0;
  char *namestr, *sumstr;
  guint namelen;
  guint32 pageid, index = 0, clientid = 0;
  guint16 pagetype, otype;
  guint32 live_new /* shut up compiler */ = 0;

  off = offset;
  if (is_ref) {
    ex = tvb_get_guint8(tvb, off);
    off += 1;
    if (exists) {
      *exists = ex;
    }
    if (ex != 0x01) {
      proto_tree_add_item(tree, hf_exists, tvb, offset, 1, TRUE);
      if (summary) {
#ifdef EPHEMERAL_BUFS
	*summary = ep_alloc(5);
#else
	*summary = g_malloc(5);
#endif
	memcpy(*summary, "None", 5);
      }
      return off;
    }
  }

  /* now get all the fields */
  flags = tvb_get_guint8(tvb, off);
  off += 1;
  pageid = tvb_get_letohl(tvb, off);
  off += 4;
  pagetype = tvb_get_letohs(tvb, off);
  off += 2;
  if (flags & 0x02) {
    unk = tvb_get_guint8(tvb, off);
    off += 1;
  }
  otype = tvb_get_letohs(tvb, off);
  off += 2;
  if (islive) {
    live_new = tvb_get_letohl(tvb, off);
    off += 4;
  }
  namestr = get_uru_string(tvb, off, &namelen);
  off += namelen;
  if (flags & 0x01) {
    /* What the wiki calls "Some ID" is an index of some sort;
       e.g. see collision messages produced by pfMarkerMgr: collision with
       MarkerRoot for user marker games. */
    index = tvb_get_letohl(tvb, off);
    off += 4;
    clientid = tvb_get_letohl(tvb, off);
    off += 4;
  }

  /* now make the summary; we need it either way */
  sumlen = strlen("Page ID: 0x Page Type: 0x Object Type: 0x "
		  "Name: Extra: 0x Index:  ClientID:  Unknown flag: 0x")+40;
  sumlen += namelen-2;
#ifdef EPHEMERAL_BUFS
  sumstr = ep_alloc(sumlen+1);
#else
  sumstr = g_malloc(sumlen+1);
#endif
  s = 0;
  if (flags > 2) {
    g_snprintf(sumstr+s, sumlen-s, "Unknown flag: 0x%02X ", flags);
    s += strlen("Unknown flag: 0x ")+2;
  }
  if (pageid != 0 || pagetype != 0) {
    g_snprintf(sumstr+s, sumlen-s, "Page ID: 0x%08X Page Type: 0x%04X ",
	       pageid, pagetype);
    s += strlen("Page ID: 0x Page Type: 0x ")+12;
  }
  else {
    /* this is kind of a degenerate case */
  }
  if (flags & 0x02) {
    g_snprintf(sumstr+s, sumlen-s, "Extra: 0x%02X ", unk);
    s += strlen("Extra: 0x ")+2;
  }
  g_snprintf(sumstr+s, sumlen-s, "Object Type: 0x%04X Name: %s",
	     otype, (namestr ? namestr : ""));
  s += strlen("Object Type: 0x Name: ")+4+namelen-2;
  if (flags & 0x01) {
    g_snprintf(sumstr+s, sumlen-s, " Index: %u ClientID: %u",
	       index, clientid);
  }

  /* now do subtree */
  if (ett >= 0) {
    ti = proto_tree_add_item(tree, hf_obj, tvb, offset, off-offset, FALSE);
    proto_item_append_text(ti, ": %s", sumstr);
    sub_tree = proto_item_add_subtree(ti, ett);

    if (is_ref) {
      tf = proto_tree_add_uint(sub_tree, hf_exists, tvb, offset, 1, ex);
      if (global_uru_hide_stuff) {
	PROTO_ITEM_SET_HIDDEN(tf);
      }
      offset += 1;
    }
    proto_tree_add_uint(sub_tree,
			(which_hf ? hf_uru_subobj_flags : hf_uru_obj_flags),
			tvb, offset, 1, flags);
    offset += 1;
    proto_tree_add_uint(sub_tree,
			(which_hf ? hf_uru_subobj_pageid : hf_uru_obj_pageid),
			tvb, offset, 4, pageid);

    offset += 4;
    proto_tree_add_uint(sub_tree,
			(which_hf ? hf_uru_subobj_pagetype : hf_uru_obj_pagetype),
			tvb, offset, 2, pagetype);
    offset += 2;
    if (flags & 0x02) {
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_uru_subobj_extra : hf_uru_obj_extra),
			  tvb, offset, 1, unk);
      offset += 1;
    }
    if (!islive) {
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_uru_subobj_type : hf_uru_obj_type),
			  tvb, offset, 2, otype);
    }
    else {
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_urulive_subobj_type : hf_urulive_obj_type),
			  tvb, offset, 2, otype);
    }
    offset += 2;
    if (islive) {
      /* XXX fill in more when you know what it is */
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_urulive_subobj_new : hf_urulive_obj_new),
			  tvb, offset, 4, live_new);
      offset += 4;
    }
    proto_tree_add_STR(sub_tree,
		       (which_hf ? hf_uru_subobj_name : hf_uru_obj_name),
		       tvb, offset, namelen, namestr);
    offset += namelen;
    if (flags & 0x01) {
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_uru_subobj_index : hf_uru_obj_index),
			  tvb, offset, 4, index);
      offset += 4;
      proto_tree_add_uint(sub_tree,
			  (which_hf ? hf_uru_subobj_clientid : hf_uru_obj_clientid),
			  tvb, offset, 4, clientid);
      offset += 4;
    }
  }
  else {
    offset = off;
  }

  /* return all the values requested */
  if (ett < 0 && summary) {
    *summary = sumstr;
  }
  else {
    MAYBE_FREE(sumstr);
  }
  if (objtype) {
    *objtype = otype;
  }
  if (name) {
    *name = namestr;
  }
  else {
    MAYBE_FREE(namestr);
  }
  return offset;
}

static struct sdl_info *
get_sdl_info(char *sdlname, guint16 version)
{
  struct sdl_info *info, *theone;
  guint i, vmax;

  theone = NULL;
  vmax = 0;
  info = all_sdls;
  while (info) {
    if (!strcmp(sdlname, info->name)) {
      if (version == info->version) {
	theone = info;
	break;
      }
      if (version == 0 && vmax == 0) {
	vmax = info->version;
	theone = info;
      }
      else if (version == 0 && info->version > vmax) {
	vmax = info->version;
	theone = info;
      }
    }
    info = info->next;
  }
  if (!theone) {
    return NULL;
  }
  if (theone->structct) {
    for (i = 0; i < theone->structct; i++) {
      if (!theone->structs[i].stype) {
	theone->structs[i].stype = get_sdl_info(theone->structs[i].type, 0);
      }
      if (!theone->structs[i].stype) {
	/* we don't have all the required SDL descriptors */
	return NULL;
      }
    }
  }
  return theone;
}

static gint
add_sdl_by_type(tvbuff_t *tvb, gint offset, proto_tree *tree,
		gint type, int count, gint treect) {
  proto_item *tf;
  int i;

  if (count <= 0) {
    return offset;
  }

  if (type == SDLTypeINT) {
    if (count > 1) {
      gint32 val32;
      tf = proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb,
				      offset, count*4, "Value: [ ");
      for (i = 0; i < count; i++) {
	val32 = tvb_get_letohl(tvb, offset);
	proto_item_append_text(tf, "%d ", val32);
	offset += 4;
      }
      proto_item_append_text(tf, "]");
    }
    else {
      proto_tree_add_item(tree, hf_uru_sdl_val_int, tvb, offset, 4, TRUE);
      offset += 4;
    }
  }
  else if (type == SDLTypeFLOAT) {
    if (count > 1) {
      gfloat valf;
      tf = proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb,
				      offset, count*4, "Value: [ ");
      for (i = 0; i < count; i++) {
	valf = tvb_get_letohieee_float(tvb, offset);
	proto_item_append_text(tf, "%f ", valf);
	offset += 4;
      }
      proto_item_append_text(tf, "]");
    }
    else {
      proto_tree_add_item(tree, hf_uru_sdl_val_float, tvb, offset, 4, TRUE);
      offset += 4;
    }
  }
  else if (type == SDLTypeBOOL || type == SDLTypeBYTE) {
    if (count > 1) {
      gint8 val8;
      tf = proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb,
				      offset, count, "Value: [ ");
      for (i = 0; i < count; i++) {
	val8 = tvb_get_guint8(tvb, offset);
	proto_item_append_text(tf, "%d ", val8);
	offset += 1;
      }
      proto_item_append_text(tf, "]");
    }
    else if (type == SDLTypeBOOL) {
      proto_tree_add_item(tree, hf_uru_sdl_val_bool, tvb, offset, 1, TRUE);
      offset += 1;
    }
    else {
      proto_tree_add_item(tree, hf_uru_sdl_val_byte, tvb, offset, 1, TRUE);
      offset += 1;
    }
  }
  else if (type == SDLTypeSHORT) {
    if (count > 1) {
      gint16 val16;
      tf = proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb,
				      offset, count*2, "Value: [ ");
      for (i = 0; i < count; i++) {
	val16 = tvb_get_letohs(tvb, offset);
	proto_item_append_text(tf, "%d ", val16);
	offset += 2;
      }
      proto_item_append_text(tf, "]");
    }
    else {
      proto_tree_add_item(tree, hf_uru_sdl_val_short, tvb, offset, 2, TRUE);
      offset += 2;
    }
  }
  else if (type == SDLTypeSTRING32) {
    for (i = 0; i < count; i++) {
      proto_tree_add_item(tree, hf_uru_sdl_val_str, tvb, offset, 32, FALSE);
      offset += 32;
    }
  }
  else if (type == SDLTypePLKEY) {
    for (i = 0; i < count; i++) {
      offset = dissect_uru_object_subtree(tvb, offset, tree, ETT_ODESC(treect),
					  NULL, FALSE, NULL, NULL, NULL,
					  -1, 1, hf_uru_sdl_val_obj);
    }
  }
  else if (type == SDLTypeCREATABLE) {
    /* should never happen */
    guint32 streamlen;
    for (i = 0; i < count; i++) {
      streamlen = tvb_get_letohl(tvb, offset);
      proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb, offset,
				 streamlen+4, "Value: plCreatable?");
      offset += streamlen+4;
    }
  }
  else if (type == SDLTypeTIME || type == SDLTypeAGETIMEOFDAY/*XXX check*/) {
    for (i = 0; i < count; i++) {
      add_uru_timestamp(tvb, offset, tree, hf_uru_sdl_val_time,
			hf_uru_sdl_val_sec, hf_uru_sdl_val_usec);
      offset += 8;
    }
  }
  else if (type == SDLTypeVECTOR3 || type == SDLTypePOINT3) {
    gfloat x, y, z;
    for (i = 0; i < count; i++) {
      x = tvb_get_letohieee_float(tvb, offset);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_x, tvb, offset,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      y = tvb_get_letohieee_float(tvb, offset+4);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_y, tvb, offset+4,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      z = tvb_get_letohieee_float(tvb, offset+8);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_z, tvb, offset+8,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      proto_tree_add_none_format(tree, hf_uru_sdl_val_3tuple, tvb,
				 offset, 12,
				 (type == SDLTypeVECTOR3
				  ? "Vector: [%f %f %f]"
				  : "Point: %f %f %f"), x, y, z);
      offset += 12;
    }
  }
  else if (type == SDLTypeQUATERNION) {
    gfloat a, b, c, d;
    for (i = 0; i < count; i++) {
      a = tvb_get_letohieee_float(tvb, offset);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_qa, tvb, offset,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      b = tvb_get_letohieee_float(tvb, offset+4);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_qb, tvb, offset+4,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      c = tvb_get_letohieee_float(tvb, offset+8);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_qc, tvb, offset+8,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      d = tvb_get_letohieee_float(tvb, offset+12);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_qd, tvb, offset+12,
			       4, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      proto_tree_add_none_format(tree, hf_uru_sdl_val_quat, tvb,
				 offset, 16, "Quaternion: %f %f %f %f",
				 a, b, c, d);
      offset += 16;
    }
  }
  else if (type == SDLTypeRGB8) {
    guint8 r, g, b;
    for (i = 0; i < count; i++) {
      r = tvb_get_guint8(tvb, offset);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_r, tvb, offset,
			       1, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      g = tvb_get_guint8(tvb, offset+1);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_g, tvb, offset+1,
			       1, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      b = tvb_get_guint8(tvb, offset+2);
      tf = proto_tree_add_item(tree, hf_uru_sdl_val_b, tvb, offset+2,
			       1, TRUE);
      PROTO_ITEM_SET_HIDDEN(tf);
      proto_tree_add_none_format(tree, hf_uru_sdl_val_clr, tvb,
				 offset, 3, "Color: %3u %3u %3u (%f %f %f)",
				 r, g, b, r/255.0, g/255.0, b/255.0);
      offset += 3;
    }
  }
  return offset;
}

/*
 * Without the SDL files for ages and without knowledge in advance about
 * the exact format for all the other SDL message types, parsing out SDL
 * values is rather heuristic, and they appear to be nestable as well.
 * So these functions separate out the parsing itself from the rest of the
 * logic.
 */
static gint
get_sdl_record(tvbuff_t *tvb, gint offset, proto_tree *tree,
	       gint bufend, int expected_len,
	       guint8 *flags, gint *len, gboolean *alcugs) {
  guint32 recognizable_thing;
  guint slen;
  gint j;
  char *str;
  guint8 intro, zero, sdlflags;
  proto_item *tf;

  *alcugs = FALSE;

  /* According to Alcugs source:
     0x02 => next byte is zero, then there is an URUSTRING, then data
     !0x02 => next is data */

  if (offset+1 > bufend) {
    return -1;
  }
  tf = proto_tree_add_item(tree, hf_uru_sdl_tagflag, tvb, offset, 1, TRUE);
  if (global_uru_hide_stuff) {
    PROTO_ITEM_SET_HIDDEN(tf);
  }
  intro = tvb_get_guint8(tvb, offset);
  offset += 1;
  if (intro == 0x02) {
    if (offset+3 > bufend) {
      return -1;
    }
    zero = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_item(tree, hf_uru_sdl_stbzero, tvb, offset, 1, TRUE);
    if (global_uru_hide_stuff && zero == 0) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    offset += 1;
    str = get_uru_string(tvb, offset, &slen);
    tf = proto_tree_add_STR(tree, hf_uru_sdl_tagstring, tvb, offset,
			    slen, str);
    if (global_uru_hide_stuff && slen == 2) {
      PROTO_ITEM_SET_HIDDEN(tf);
    }
    MAYBE_FREE(str);
    offset += slen;
  }
  if (offset+1 > bufend) {
    return -1;
  }
  sdlflags = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_uru_sdl_entryflags, tvb, offset, 1, TRUE);
  offset += 1;
  if (intro != 0x02 && !(sdlflags & SDLFlagNoData)) {
    *alcugs = TRUE;
    *len = bufend-offset; /* in case it's the only record */
    return offset;
  }

  *flags = sdlflags;
  if (sdlflags & SDLFlagTimestamp) {
    if (offset+8 > bufend) {
      return -1;
    }
    add_uru_timestamp(tvb, offset, tree, hf_uru_sdl_timestamp,
		      hf_uru_sdl_ts_sec, hf_uru_sdl_ts_usec);
    offset += 8;
  }
  if (sdlflags & SDLFlagNoData) {
    gint where;
    where = offset - 1;
    if (sdlflags & SDLFlagTimestamp) {
      where -= 8;
    }
    proto_tree_add_boolean_format(tree, hf_uru_sdl_val_default,
				  tvb, where, 1, 1, "Default value");
    *len = 0;
    return offset;
  }

  if (expected_len >= 0) {
    if (offset+expected_len > bufend) {
      return -1;
    }
    *len = expected_len;
    return offset;
  }
  /* now, we can't know how long the record is without the SDL file
     so we guess, ick! */
  j = 0;
  recognizable_thing = 0;
  while (offset+j+5 <= bufend) {
    recognizable_thing = tvb_get_letohl(tvb, offset+j);
    if (recognizable_thing == 0xf0000002) {
      break;
    }
    j++;
  }
  if (recognizable_thing != 0xf0000002) {
    /* we got to the end of the buffer so assume it's the last record */
    *len = bufend-offset;
  }
  else {
    *len = j;
  }
  return offset;
}

static void
add_record_guess(tvbuff_t *tvb, gint offset, proto_tree *tree, int len) {
  char *string;
  guint8 val8;
  int i, zeros;
  proto_item *ti;

  if (len == 1) {
    /* bool, byte */
    add_sdl_by_type(tvb, offset, tree, SDLTypeBYTE, 1, 0/*unused*/);
  }
  else if (len == 2) {
    /* short */
    add_sdl_by_type(tvb, offset, tree, SDLTypeSHORT, 1, 0/*unused*/);
  }
  else if (len == 4) {
    /* int */
    add_sdl_by_type(tvb, offset, tree, SDLTypeINT, 1, 0/*unused*/);
  }
  else if (len <= 0) {
    ti = proto_tree_add_boolean_format(tree, hf_uru_dissection_error, tvb,
				       offset, 0, 1,
				       "Zero-length field found!");
    PROTO_ITEM_SET_GENERATED(ti);
  }
  else {
    /* string, array of more than one */
    zeros = 0;
    for (i = 0; i < len; i++) {
      val8 = tvb_get_guint8(tvb, offset+i);
      if (val8 < 0x20 || val8 > 0x7e) {
	if (val8 == 0) {
	  zeros = 1;
	}
	else {
	  break;
	}
      }
      else if (zeros) {
	break;
      }
    }
#ifdef EPHEMERAL_BUFS
    string = tvb_get_ephemeral_string(tvb, offset, len);
#else
    string = (char*)tvb_get_string(tvb, offset, len);
#endif
    if (len == 32 && i == len && string[0]) {
      /* probably a string, but definitely printable in any case */
      add_sdl_by_type(tvb, offset, tree, SDLTypeSTRING32, 1, 0/*unused*/);
    }
    else if (len == 8) {
      /* these seem to usually be timestamps */
      add_sdl_by_type(tvb, offset, tree, SDLTypeAGETIMEOFDAY, 1, 0/*unused*/);
    }
    else {
      /* array of values, maybe */
      char *buf;
#ifdef EPHEMERAL_BUFS
      buf = ep_alloc((len*3)+1);
#else
      buf = g_malloc((len*3)+1);
#endif
      for (i = 0; i < len; i++) {
	g_snprintf(buf+(i*3), 4, "%02X ", (guint8)string[i]);
      }
      buf[(len*3)-1] = '\0';
      proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb,
				 offset, len, "Value: %s", buf);
#ifndef EPHEMERAL_BUFS
      g_free(buf);
#endif
    }
#ifndef EPHEMERAL_BUFS
    g_free(string);
#endif
  }
}

static void
add_record_array(tvbuff_t *tvb, gint offset, proto_tree *tree, int len) {
  guint32 count;
  guint size, i, j;
  proto_item *tf;
  char *string;

  if (len < 4) {
    add_record_guess(tvb, offset, tree, len);
    return;
  }
  count = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_uru_sdl_arrct, tvb, offset, 4, TRUE);
  offset += 4;
  len -= 4;
  size = (guint)len / count;
  if (size == 1) {
    /* bool, byte */
    offset = add_sdl_by_type(tvb, offset, tree, SDLTypeBYTE, count, 0);
  }
  else if (size == 2) {
    offset = add_sdl_by_type(tvb, offset, tree, SDLTypeSHORT, count, 0);
  }
  else if (size == 4) {
    /* int */
    offset = add_sdl_by_type(tvb, offset, tree, SDLTypeINT, count, 0);
  }
  else {
    tf = proto_tree_add_none_format(tree, hf_uru_sdl_val_arr, tvb, offset,
				    (int)(count*size), "Value: [");
    for (i = 0; i < count; i++) {
#ifdef EPHEMERAL_BUFS
      string = tvb_get_ephemeral_string(tvb, offset, size);
#else
      string = (char*)tvb_get_string(tvb, offset, size);
#endif
      proto_item_append_text(tf, " (");
      for (j = 0; j < size; j++) {
	proto_item_append_text(tf, "%s%02X", j == 0 ? "" : ",",
			       (guint8)string[j]);
      }
      proto_item_append_text(tf, ")");
#ifndef EPHEMERAL_BUFS
      g_free(string);
#endif
      offset += size;
    }
    proto_item_append_text(tf, " ]");
  }
  len -= (gint)(count*size);
  if (len > 0) {
#ifdef EPHEMERAL_BUFS
    string = tvb_get_ephemeral_string(tvb, offset, len);
#else
    string = (char*)tvb_get_string(tvb, offset, len);
#endif
    tf = proto_tree_add_text(tree, tvb, offset, len, " Extra data: (");
    for (j = 0; j < (guint)len; j++) {
      proto_item_append_text(tf, "%s%02X", j == 0 ? "" : ",",
			     (guint8)string[j]);
    }
    proto_item_append_text(tf, ")");
#ifndef EPHEMERAL_BUFS
    g_free(string);
#endif
  }
}

static gint
add_vault_node(tvbuff_t *tvb, gint offset, proto_tree *tree, guint32 *idx) {
  guint32 unk32, mask1, mask2, nodetype;
  proto_item *tf;
  char *str;
  guint slen;

  /* vault_parse_node */
  unk32 = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_uru_vault_node_masklen, tvb, offset,
		      4, TRUE);
  offset += 4;
  mask1 = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_uru_vault_node_mask1, tvb, offset,
		      4, TRUE);
  offset += 4;
  if (unk32 == 2) {
    mask2 = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_vault_node_mask2, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  else {
    mask2 = 0;
  }
  unk32 = tvb_get_letohl(tvb, offset);
  if (idx) {
    *idx = unk32;
  }
  proto_tree_add_item(tree, hf_uru_vault_node_index, tvb, offset,
		      4, TRUE);
  tf = proto_tree_add_item(tree, hf_uru_node_trackid, tvb, offset,
			   4, TRUE);
  PROTO_ITEM_SET_HIDDEN(tf);
  offset += 4;
  nodetype = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_uru_vault_node_type, tvb, offset,
		      1, TRUE);
  offset += 1;
  proto_tree_add_item(tree, hf_uru_vault_node_perm, tvb, offset,
		      4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_uru_vault_node_owner, tvb, offset,
		      4, TRUE);
  offset += 4;
  unk32 = tvb_get_letohl(tvb, offset);
  tf = proto_tree_add_item(tree, hf_uru_vault_node_unk1, tvb, offset,
			   4, TRUE);
  if (global_uru_hide_stuff && unk32 == 0) {
    PROTO_ITEM_SET_HIDDEN(tf);
  }
  offset += 4;
  add_uru_timestamp(tvb, offset, tree, hf_uru_vault_node_ts,
		    hf_uru_vault_node_sec, hf_uru_vault_node_usec);
  offset += 8;
  if (mask1 & MId1) {
    proto_tree_add_item(tree, hf_uru_vault_node_id1, tvb,
			offset, 4, TRUE);
    offset += 4;
  }
  if (mask1 & MStamp2) {
    add_uru_timestamp(tvb, offset, tree, hf_uru_vault_node_ts2,
		      hf_uru_vault_node_sec2, hf_uru_vault_node_usec2);
    offset += 8;
  }
  if (mask1 & MAgeCoords) { /* a bit of a misnomer */
    add_uru_timestamp(tvb, offset, tree, hf_uru_vault_node_ts3,
		      hf_uru_vault_node_sec3, hf_uru_vault_node_usec3);
    offset += 8;
  }
  if (mask1 & MAgeName) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_agename, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MHexGuid) {
    proto_tree_add_item(tree, hf_uru_vault_node_hexguid, tvb, offset,
			8, TRUE);
    offset += 8;
  }
  if (mask1 & MTorans) {
    proto_tree_add_item(tree, hf_uru_vault_node_ftype, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MDistance) {
    proto_tree_add_item(tree, hf_uru_vault_node_dist, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MElevation) {
    proto_tree_add_item(tree, hf_uru_vault_node_elev, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MUnk5) {
    proto_tree_add_item(tree, hf_uru_vault_node_unk5, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MId2) {
    proto_tree_add_item(tree, hf_uru_vault_node_id2, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MUnk7) {
    proto_tree_add_item(tree, hf_uru_vault_node_unk7, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MUnk8) {
    proto_tree_add_item(tree, hf_uru_vault_node_unk8, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MUnk9) {
    proto_tree_add_item(tree, hf_uru_vault_node_unk9, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & MEntryName) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_entryname, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MSubEntry) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_subentry, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MOwnerName) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_ownername, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MGuid) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_guid, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MStr1) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_str1, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MStr2) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_str2, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MAvie) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_avname, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MUid) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_uid, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MEValue) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_entry, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MEntry2) {
    str = get_uru_string(tvb, offset, &slen);
    proto_tree_add_STR(tree, hf_uru_vault_node_entry2, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & MData1) {
    unk32 = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_vault_node_dsize, tvb, offset,
			4, TRUE);
    offset += 4;
    if (unk32 > 0) {
      tf = proto_tree_add_item(tree, hf_uru_vault_node_data, tvb, offset,
			       unk32, TRUE);
      if (nodetype == KSDLNode) {
	proto_tree *sdl_tree;
	guint16 flag16;
	gint noffset;

	sdl_tree = proto_item_add_subtree(tf, ett_sdl_subsdl);
	flag16 = tvb_get_letohs(tvb, offset);
	tf = proto_tree_add_item(sdl_tree, hf_uru_gamemsg_type, tvb,
				 offset, 2, TRUE);
	if (global_uru_hide_stuff && flag16 == 0x8000) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset = offset + 2;
	noffset = dissect_sdl_msg(tvb, noffset, sdl_tree, offset+unk32);
	if (noffset - offset < (gint)unk32) {
	  tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					     tvb, noffset,
					     unk32 - (noffset-offset), 1,
					     "Too much data");
	  PROTO_ITEM_SET_GENERATED(tf);
	}
      }
      offset += unk32;
    }
  }
  if (mask1 & MData2) {
    unk32 = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_uru_vault_node_d2size, tvb, offset,
			4, TRUE);
    offset += 4;
    if (unk32 > 0) {
      proto_tree_add_item(tree, hf_uru_vault_node_data2, tvb, offset,
			  unk32, TRUE);
      offset += unk32;
    }
  }
  if (mask2 & MBlob1) {
    proto_tree_add_item(tree, hf_uru_vault_node_blob1, tvb, offset,
			8, TRUE);
    offset += 8;
  }
  if (mask2 & MBlob2) {
    proto_tree_add_item(tree, hf_uru_vault_node_blob2, tvb, offset,
			8, TRUE);
    offset += 8;
  }

  return offset;
}

static gint
add_live_vault_node(tvbuff_t *tvb, gint offset, proto_tree *tree) {
  guint32 nodetype = 0, mask1, mask2, timecnv, len;
  proto_item *tf, *ti;
  char *str;
  guint slen;
  proto_tree *sub_tree = NULL;

  /* parse Live vault node - merge with add_vault_node later? */

  mask1 = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_uru_vault_node_mask1, tvb, offset,
		      4, TRUE);
  offset += 4;
  mask2 = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_uru_vault_node_mask2, tvb, offset,
			4, TRUE);
  offset += 4;
  if (mask1 & kNodeId) {
    proto_tree_add_item(tree, hf_urulive_vault_nodeid, tvb, offset,
			4, TRUE);
    tf = proto_tree_add_item(tree, hf_uru_node_trackid, tvb, offset,
			     4, TRUE);
    PROTO_ITEM_SET_HIDDEN(tf);
    offset += 4;
  }
  if (mask1 & kCreateTime) {
    timecnv = tvb_get_letohl(tvb,offset);
    tf = proto_tree_add_item(tree, hf_urulive_vault_createtime, tvb,
			offset, 4, TRUE);
    append_ts_formatted(tf, timecnv, 0, FALSE);
    offset += 4;
  }
  if (mask1 & kModifyTime) {
    timecnv = tvb_get_letohl(tvb,offset);
    tf = proto_tree_add_item(tree, hf_urulive_vault_modifytime, tvb,
			offset, 4, TRUE);
    append_ts_formatted(tf, timecnv, 0, FALSE);
    offset += 4;
  }
  if (mask1 & kCreateAgeName) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(tree, hf_urulive_vault_createagename, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kCreateAgeUuid) {
    tf = proto_tree_add_item(tree, hf_urulive_vault_createageuuid, tvb,
			     offset, 16, TRUE);
    append_uru_uuid(tf, tvb, offset);
    offset += 16;
  }
  if (mask1 & kCreatorAcct) {
    tf = proto_tree_add_item(tree, hf_urulive_vault_creatoracctid, tvb,
			     offset, 16, TRUE);
    append_uru_uuid(tf, tvb, offset);
    offset += 16;
  }
  if (mask1 & kCreatorId) {
    proto_tree_add_item(tree, hf_urulive_vault_creatorid, tvb, offset,
			4, TRUE);
    tf = proto_tree_add_item(tree, hf_uru_node_trackid, tvb, offset,
			     4, TRUE);
    PROTO_ITEM_SET_HIDDEN(tf);
    offset += 4;
  }
  if (mask1 & kNodeType) { /* this is always here, so far */
    nodetype = tvb_get_letohl(tvb, offset);
    tf = proto_tree_add_item(tree, hf_urulive_vault_nodetype, tvb,
			     offset, 4, TRUE);
    offset += 4;
    sub_tree = proto_item_add_subtree(tf, ett_vault_nodes);
  }
  else {
    /* just in case */
    sub_tree = tree;
  }

  if (mask1 & kInt32_1) {
    int hf;

    if (nodetype == KPlayerInfoNode) {
      hf = hf_urulive_vault_online;
    }
    else if (nodetype == KPlayerInfoListNode || nodetype == KFolderNode
	     || nodetype == KAgeInfoListNode) {
      hf = hf_urulive_vault_foldertype;
    }
    else if (nodetype == KImageNode) {
      hf = hf_urulive_vault_imgexists;
    }
    else if (nodetype == KChronicleNode) {
      hf = hf_urulive_vault_type;
    }
    else if (nodetype == KAgeInfoNode) {
      hf = hf_urulive_age_inum;
    }
    else {
      hf = hf_urulive_vault_int32_1;
    }
    proto_tree_add_item(sub_tree, hf, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & kInt32_2) {
    if (nodetype == KAgeInfoNode) {
      tf = proto_tree_add_item(sub_tree, hf_urulive_age_public32, tvb, offset,
			       4, TRUE);
    }
    else {
      tf = proto_tree_add_item(sub_tree, hf_urulive_vault_int32_2, tvb, offset,
			       4, TRUE);
    }
    if (nodetype == KPlayerInfoNode) {
      guint32 flag;
      flag = tvb_get_letohl(tvb, offset);
      if (flag & 0x04) {
	/* ResEng hidden flag (in buddies list on left, but absent in all
	   lists in the big KI), there probably is another more-hidden flag */
	proto_item_append_text(tf, " (Mostly Hidden)");
      }
    }
    offset += 4;
  }
  if (mask1 & kInt32_3) {
    proto_tree_add_item(sub_tree, hf_urulive_vault_int32_3, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & kInt32_4) {
    proto_tree_add_item(sub_tree, hf_urulive_vault_int32_4, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & kUInt32_1) {
    if (nodetype == KPlayerInfoNode) {
      proto_tree_add_item(sub_tree, hf_urulive_vault_owner, tvb, offset,
			4, TRUE);
    }
    else if (nodetype == KAgeInfoNode) {
      proto_tree_add_item(sub_tree, hf_urulive_vault_creatorid, tvb, offset,
			  4, TRUE);
    }
    else {
      proto_tree_add_item(sub_tree, hf_urulive_vault_uint32_1, tvb, offset,
			  4, TRUE);
    }
    offset += 4;
  }
  if (mask1 & kUInt32_2) {
    if (nodetype == KAgeLinkNode) {
      proto_tree_add_item(sub_tree, hf_urulive_vault_volatile, tvb, offset,
			  4, TRUE);
    }
    else {
      proto_tree_add_item(sub_tree, hf_urulive_vault_uint32_2, tvb, offset,
			  4, TRUE);
    }
    offset += 4;
  }
  if (mask1 & kUInt32_3) {
    proto_tree_add_item(sub_tree, hf_urulive_vault_uint32_3, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & kUInt32_4) {
    proto_tree_add_item(sub_tree, hf_urulive_vault_uint32_4, tvb, offset,
			4, TRUE);
    offset += 4;
  }
  if (mask1 & kUuid_1) {
    if (nodetype == KPlayerInfoNode || nodetype == KVNodeMgrAgeNode
	|| nodetype == KAgeInfoNode) {
      ti = proto_tree_add_item(sub_tree, hf_urulive_vault_ageUUID, tvb, offset,
			       16, TRUE);
    }
    else if (nodetype == KVNodeMgrPlayerNode) {
      ti = proto_tree_add_item(sub_tree, hf_urulive_vault_acct, tvb, offset,
			       16, TRUE);
    }
    else {
      ti = proto_tree_add_item(sub_tree, hf_urulive_vault_uuid_1, tvb, offset,
			       16, TRUE);
    }
    append_uru_uuid(ti, tvb, offset);
    offset += 16;
  }
  if (mask1 & kUuid_2) {
    if (nodetype == KVNodeMgrAgeNode || nodetype == KAgeInfoNode) {
      ti = proto_tree_add_item(sub_tree, hf_urulive_vault_parentUUID,
			       tvb, offset, 16, TRUE);
    }
    else {
      ti = proto_tree_add_item(sub_tree, hf_urulive_vault_uuid_2, tvb, offset,
			       16, TRUE);
    }
    append_uru_uuid(ti, tvb, offset);
    offset += 16;
  }
  if (mask1 & kUuid_3) {
    ti = proto_tree_add_item(sub_tree, hf_urulive_vault_uuid_3, tvb, offset,
			     16, TRUE);
    append_uru_uuid(ti, tvb, offset);
    offset += 16;
  }
  if (mask1 & kUuid_4) {
    ti = proto_tree_add_item(sub_tree, hf_urulive_vault_uuid_4, tvb, offset,
			     16, TRUE);
    append_uru_uuid(ti, tvb, offset);
    offset += 16;
  }
  if (mask1 & kString64_1) {
    int hf;

    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    if (nodetype == KPlayerInfoNode
	|| nodetype == KPlayerInfoListNode || nodetype == KFolderNode) {
      hf = hf_urulive_vault_agename;
    }
    else if (nodetype == KVNodeMgrPlayerNode) {
      hf = hf_urulive_create_gender;
    }
    else if (nodetype == KImageNode) {
      hf = hf_urulive_vault_imagename;
    }
    else if (nodetype == KChronicleNode || nodetype == KTextNoteNode) {
      hf = hf_urulive_vault_name;
    }
    else if (nodetype == KSDLNode) {
      hf = hf_uru_sdl_sdlname;
    }
    else if (nodetype == KVNodeMgrAgeNode) {
      hf = hf_urulive_vault_age_fname;
    }
    else {
      hf = hf_urulive_vault_string64_1;
    }
    proto_tree_add_STR(sub_tree, hf, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kString64_2) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_string64_2, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kString64_3) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_string64_3, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kString64_4) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_string64_4, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kString64_5) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_string64_5, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kString64_6) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_string64_6, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kIString64_1) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    if (nodetype == KPlayerInfoNode || nodetype == KVNodeMgrPlayerNode) {
      proto_tree_add_STR(sub_tree, hf_urulive_vault_name, tvb,
			 offset, slen, str);
    }
    else {
      proto_tree_add_STR(sub_tree, hf_urulive_vault_istring64_1, tvb,
			 offset, slen, str);
    }
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kIString64_2) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_istring64_2, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kText_1) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    if (nodetype == KMarkerListNode) {
      proto_tree_add_STR(sub_tree, hf_urulive_vault_name, tvb,
			 offset, slen, str);
    }
    else if (nodetype == KChronicleNode || nodetype == KTextNoteNode) {
      proto_tree_add_STR(sub_tree, hf_urulive_vault_value, tvb,
			 offset, slen, str);
    }
    else {
      proto_tree_add_STR(sub_tree, hf_urulive_vault_text_1, tvb,
			 offset, slen, str);
    }
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kText_2) {
    slen = tvb_get_letohl(tvb, offset);
    str = get_widestring(tvb, offset+4, &slen);
    slen += 4;
    proto_tree_add_STR(sub_tree, hf_urulive_vault_text_2, tvb,
		       offset, slen, str);
    MAYBE_FREE(str);
    offset += slen;
  }
  if (mask1 & kBlob_1) {
    if (nodetype == KImageNode) {
      len = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(sub_tree, hf_urulive_vault_imagelen, tvb,
			  offset, 4, TRUE);
      offset += 4;
      proto_tree_add_item(sub_tree, hf_urulive_vault_image, tvb,
			offset, len, TRUE);
      offset += len;
    }
    else if (nodetype == KAgeLinkNode) {
      len = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(sub_tree, hf_urulive_vault_len, tvb,
			  offset, 4, TRUE);
      offset += 4;
#ifdef EPHEMERAL_BUFS
      str = tvb_get_ephemeral_string(tvb, offset, len);
#else
      str = tvb_get_string(tvb, offset, len);
#endif
      proto_tree_add_STR(sub_tree, hf_urulive_vault_linkpoint, tvb,
			 offset, len, str);
      MAYBE_FREE(str);
      offset += len;
    }
    else {
      len = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(sub_tree, hf_urulive_vault_len, tvb,
			offset, 4, TRUE);
      offset += 4;
      tf = proto_tree_add_item(sub_tree, hf_urulive_vault_blob_1, tvb,
			       offset, len, TRUE);
      if (nodetype == KSDLNode) {
	proto_tree *sdl_tree;
	guint16 flag16;
	gint noffset;

	sdl_tree = proto_item_add_subtree(tf, ett_sdl_subsdl);
	flag16 = tvb_get_letohs(tvb, offset);
	tf = proto_tree_add_item(sdl_tree, hf_uru_gamemsg_type, tvb,
				 offset, 2, TRUE);
	if (global_uru_hide_stuff && flag16 == 0x8000) {
	  PROTO_ITEM_SET_HIDDEN(tf);
	}
	noffset = offset + 2;
	noffset = dissect_sdl_msg(tvb, noffset, sdl_tree, offset+len);
	if (noffset - offset < (gint)len) {
	  tf = proto_tree_add_boolean_format(sub_tree, hf_uru_dissection_error,
					     tvb, noffset,
					     len - (noffset-offset), 1,
					     "Too much data");
	  PROTO_ITEM_SET_GENERATED(tf);
	}
      }
      offset += len;
    }
  }
  if (mask1 & kBlob_2) {
    len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(sub_tree, hf_urulive_vault_len, tvb,
			offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(sub_tree, hf_urulive_vault_blob_2, tvb,
			offset, len, TRUE);
    offset += len;
  }
  return offset;
}

static void append_uru_uuid(proto_item *ti, tvbuff_t *tvb, gint offset) {
  guint32 data1;
  guint16 data2, data3;
  char *data4, *data5;
  guint i;

  data1 = tvb_get_letohl(tvb, offset);
  data2 = tvb_get_letohs(tvb, offset+4);
  data3 = tvb_get_letohs(tvb, offset+6);
  data4 = tvb_bytes_to_str(tvb, offset+8, 2);
  data5 = tvb_bytes_to_str(tvb, offset+10, 6);
  for (i = 0; i < strlen(data4); i++) {
    data4[i] = (char)tolower((int)data4[i]);
  }
  for (i = 0; i < strlen(data5); i++) {
    data5[i] = (char)tolower((int)data5[i]);
  }
  proto_item_append_text(ti, " (%08x-%04x-%04x-%s-%s)", data1,
              data2, data3, data4, data5);
}



/********** plugin hooks **********/

/* port range logic borrowed from plugins/packet-asn1.c */
static void
register_uru_port(guint32 port) {
  dissector_add("udp.port", port, uru_handle);
}

static void
unregister_uru_port(guint32 port) {
  dissector_delete("udp.port", port, uru_handle);
}

#if defined(_WIN32) && defined(GSCANNER_IS_BROKEN)
#include "scanner-code.c"
#else
#define my_g_scanner_get_next_token g_scanner_get_next_token
#endif

struct sdl_info *
uru_load_sdl_files(const char *path) {
  struct sdl_info *info, *head, *tail, *prev;
  WS_DIR *d;
  WS_DIRENT *de;
  int len;
  char *fname;
  FILE *f;
  /* for parsing */
  GScanner *scan;
  GTokenType type;
  int in_desc, state;

  d = ws_dir_open(path, 0, NULL/* GError** */);
  if (!d) {
    return NULL;
  }

  scan = g_scanner_new(NULL);
  scan->config->cset_identifier_first = G_CSET_a_2_z "_" G_CSET_A_2_Z "$";
  scan->config->scan_comment_multi = 0;
  scan->config->scan_symbols = 0;
  scan->config->scan_octal = 0;
  scan->config->scan_hex_dollar = 0;
  scan->config->scan_string_sq = 0;
  head = tail = prev = NULL;
  info = NULL;

  while ((de = ws_dir_read_name(d)) != NULL) {
    len = strlen(ws_dir_get_name(de));
    if (len < 5) {
      continue;
    }
    if (g_ascii_strcasecmp(".sdl", ws_dir_get_name(de)+(len-4))) {
      continue;
    }
    len = strlen(path)+strlen(ws_dir_get_name(de))+2;
    fname = g_malloc(len);
    g_snprintf(fname, len, "%s%s%s", path, G_DIR_SEPARATOR_S,
	       ws_dir_get_name(de));
    if ((f = ws_fopen(fname, "r")) == NULL) {
      g_free(fname);
      continue;
    }
    g_free(fname);

    g_scanner_input_file(scan, fileno(f));
    in_desc = 0;
    info = NULL;
    state = 0;
    while (!g_scanner_eof(scan)) {
      type = my_g_scanner_get_next_token(scan);
      if (type == G_TOKEN_IDENTIFIER) {
	if (!in_desc) {
	  if (!g_ascii_strcasecmp(scan->value.v_identifier, "STATEDESC")) {
	    in_desc = 1;
	    continue;
	  }
	}
	if (info == NULL) {
	  info = (struct sdl_info *)g_malloc(sizeof(struct sdl_info));
	  memset((char *)info, 0, sizeof(struct sdl_info));
	  info->name = g_strdup(scan->value.v_identifier);
	  continue;
	}
	if (info->version == 0) {
	  /* this had better be "VERSION" */
	  continue;
	}
	if (!g_ascii_strcasecmp(scan->value.v_identifier, "VAR")) {
	  /* state had better be 0 */
	  state = 1;
	  continue;
	}
	if (state == 1) {
	  char *t;
	  int type = -1;

	  t = scan->value.v_identifier;
	  if (!g_ascii_strcasecmp(t, "INT")) {
	    type = SDLTypeINT;
	  }
	  else if (!g_ascii_strcasecmp(t, "FLOAT")) {
	    type = SDLTypeFLOAT;
	  }
	  else if (!g_ascii_strcasecmp(t, "BOOL")) {
	    type = SDLTypeBOOL;
	  }
	  else if (!g_ascii_strcasecmp(t, "STRING32")) {
	    type = SDLTypeSTRING32;
	  }
	  else if (!g_ascii_strcasecmp(t, "PLKEY")) {
	    type = SDLTypePLKEY;
	  }
	  else if (!g_ascii_strcasecmp(t, "CREATABLE")) {
	    type = SDLTypeCREATABLE;
	  }
	  else if (!g_ascii_strcasecmp(t, "TIME")) {
	    type = SDLTypeTIME;
	  }
	  else if (!g_ascii_strcasecmp(t, "BYTE")) {
	    type = SDLTypeBYTE;
	  }
	  else if (!g_ascii_strcasecmp(t, "SHORT")) {
	    type = SDLTypeSHORT;
	  }
	  else if (!g_ascii_strcasecmp(t, "AGETIMEOFDAY")) {
	    type = SDLTypeAGETIMEOFDAY;
	  }
	  else if (!g_ascii_strcasecmp(t, "VECTOR3")) {
	    type = SDLTypeVECTOR3;
	  }
	  else if (!g_ascii_strcasecmp(t, "POINT3")) {
	    type = SDLTypePOINT3;
	  }
	  else if (!g_ascii_strcasecmp(t, "QUATERNION")) {
	    type = SDLTypeQUATERNION;
	  }
	  else if (!g_ascii_strcasecmp(t, "RGB8")) {
	    type = SDLTypeRGB8;
	  }
	  else if (t[0] == '$') {
	    /* struct */
	  }
	  else {
	    /* problem */
	    fprintf(stderr, "unknown VAR type %s\n", t);
	    state = 0;
	    continue;
	  }

	  if (type >= 0) {
	    struct sdl_var *var;

	    if (info->varct) {
	      info->vars = (struct sdl_var *)
		g_realloc((void *)info->vars,
			  sizeof(struct sdl_var)*(++info->varct));
	    }
	    else {
	      info->vars = (struct sdl_var *)
		g_malloc(sizeof(struct sdl_var)*(++info->varct));
	    }
	    var = &info->vars[(info->varct)-1];
	    memset((char*)var, 0, sizeof(struct sdl_var));
	    var->type = type;
	    state = 2;
	  }
	  else {
	    struct sdl_struct *st;

	    if (info->structct) {
	      info->structs = (struct sdl_struct *)
		g_realloc((void *)info->structs,
			  sizeof(struct sdl_struct)*(++info->structct));
	    }
	    else {
	      info->structs = (struct sdl_struct *)
		g_malloc(sizeof(struct sdl_struct)*(++info->structct));
	    }
	    st = &info->structs[(info->structct)-1];
	    memset((char*)st, 0, sizeof(struct sdl_struct));
	    /* XXX search for correct one */
	    st->type = g_strdup(t+1);
	    state = 3;
	  }
	}
	else if (state == 2) {
	  info->vars[(info->varct)-1].name
	    = g_strdup(scan->value.v_identifier);
	  state = 4;
	}
	else if (state == 3) {
	  info->structs[(info->structct)-1].name
	    = g_strdup(scan->value.v_identifier);
	  state = 5;
	}
      }
      else if (type == G_TOKEN_LEFT_BRACE) {
	/* state better be 4 or 5 */
	state += 4;
	continue;
      }
      else if (type == G_TOKEN_RIGHT_BRACE) {
	state = 0;
      }
      else if (type == G_TOKEN_RIGHT_CURLY) {
	/* end of desc */
	if (!info) {
	  /* problem! */
	  continue;
	}
	if (prev) {
	  if (!strcmp(prev->name, info->name)) {
	    /* put at end of list */
	    if (tail) {
	      tail->next = prev;
	    }
	    else {
	      head = prev;
	    }
	    tail = prev;
	  }
	  else {
	    /* put at beginning of list */
	    prev->next = head;
	    head = prev;
	    if (!tail) {
	      tail = prev;
	    }
	  }
	}
	prev = info;
	info = NULL;
	in_desc = 0;
	continue;
      }
      else if (type == G_TOKEN_INT) {
	if (info->version == 0) {
	  info->version = scan->value.v_int;
	  continue;
	}
	if (state == 8) {
	  info->vars[(info->varct)-1].count = scan->value.v_int;
	  state = 10;
	}
	else if (state == 9) {
	  info->structs[(info->structct)-1].count = scan->value.v_int;
	  state = 10;
	}
      }
    } /* while (!g_scanner_eof(scan)) */
    if (info) {
      /* truncated SDL file (see city.sdl) */
      guint i;
      if (info->varct) {
	for (i = 0; i < info->varct; i++) {
	  g_free(info->vars[i].name);
	}
	g_free(info->vars);
      }
      if (info->structct) {
	for (i = 0; i < info->structct; i++) {
	  g_free(info->structs[i].name);
	  g_free(info->structs[i].type);
	}
	g_free(info->structs);
      }
      info = NULL;
    }
    fclose(f);
  } /* while ((de = ws_dir_read_name(d)) != NULL) */
  ws_dir_close(d);
  g_scanner_destroy(scan);
  if (prev && info) {
    if (!strcmp(prev->name, info->name)) {
      /* put at end of list */
      if (tail) {
	tail->next = prev;
      }
      else {
	head = prev;
      }
      tail = prev;
    }
    else {
      /* put at beginning of list */
      prev->next = head;
      head = prev;
      if (!tail) {
	tail = prev;
      }
    }
  }
  else if (prev) {
    prev->next = head;
    head = prev;
  }
  else if (info) {
    info->next = head;
    head = info;
  }
  return head;
}

void
proto_reg_handoff_uru(void) {
  static gboolean inited = FALSE;

  if (!inited) {
    uru_handle = create_dissector_handle(dissect_uru, proto_uru);
    inited = TRUE;
  }
  if (uru_port_range != NULL) {
    range_foreach(uru_port_range, unregister_uru_port);
    g_free(uru_port_range);
  }
  uru_port_range = range_copy(global_uru_port_range);
  range_foreach(uru_port_range, register_uru_port);
  if (all_sdls) {
    struct sdl_info *info, *next;
    guint i;

    info = all_sdls;
    while (info) {
      next = info->next;
      if (info->varct) {
	for (i = 0; i < info->varct; i++) {
	  g_free(info->vars[i].name);
	}
	g_free(info->vars);
      }
      if (info->structct) {
	for (i = 0; i < info->structct; i++) {
	  g_free(info->structs[i].type);
	  g_free(info->structs[i].name);
	}
	g_free(info->structs);
      }
      g_free(info);
      info = next;
    }
    all_sdls = NULL;
  }
  if (global_uru_load_sdls) {
    /* TODO: maybe someday allow loading only as requested */
    /* I don't want to do this but anything else would require tons of
       special code */
    all_sdls = uru_load_sdl_files(global_uru_sdl_path);
  }
}

static void
uru_init_protocol(void) {
  fragment_table_init(&uru_fragment_table);
  reassembled_table_init(&uru_reassembled_table);
}

/* Register the protocol with Wireshark */
void
proto_register_uru(void)
{
  module_t *uru_module;

  char tmpstr[64];

  /* Register the protocol name and description */
  if (proto_uru == -1) {
    proto_uru = proto_register_protocol (
			"Uru Protocol",		/* name */
			"Uru",			/* short name */
			"uru"			/* abbrev */
			);
  }

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_uru, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register preferences module (See Section 2.6 for more on preferences) */
  uru_module = prefs_register_protocol(proto_uru, proto_reg_handoff_uru);

  g_snprintf(tmpstr, sizeof(tmpstr), "%u-%u", URU_PORT_LOW, URU_PORT_HIGH);
  range_convert_str(&global_uru_port_range, tmpstr, 65535);
  prefs_register_range_preference(uru_module, "udp_ports", "Uru Port Range",
				  "Set the port range for Uru messages",
				  &global_uru_port_range, 65535);
  prefs_register_bool_preference(uru_module, "alcugs_format",
				 "Header Format",
				 "Show Alcugs-style header info",
				 &global_uru_header_style);
  prefs_register_bool_preference(uru_module, "summary_acks",
				 "Show Ack Info",
				 "Show packet number & ack info in summary",
				 &global_uru_summary_ack);
  prefs_register_bool_preference(uru_module, "vault_streams",
				 "Dissect Vault Streams",
				 "Fully dissect vault manifest & nodes",
				 &global_uru_parse_vault_streams);
  prefs_register_bool_preference(uru_module, "hide_stuff",
				 "Hide Useless Fields",
				 "Do not show certain constant, unknown field "
				 "values",
				 &global_uru_hide_stuff);
  prefs_register_bool_preference(uru_module, "load_sdl", "Load SDL",
				 "Load SDL definitions from files in a "
				 "directory (change prefs to reload all SDLs)",
				 &global_uru_load_sdls);
  prefs_register_string_preference(uru_module, "sdl_dir", "SDL Directory",
				   "Load (unencrypted) SDL files from this "
				   "directory",
				   &global_uru_sdl_path);

  /* Register protocol init routine */
  register_init_routine(uru_init_protocol);
}



/* Code to actually dissect the packets */
static void
dissect_urulive_message(tvbuff_t *etvb,
			packet_info *pinfo, proto_tree *tree,
			guint32 seq) {

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti = NULL;
  proto_tree *uru_tree = NULL;
  tvbuff_t *tvb;

  gint offset = 0;
  proto_item *tf;
  proto_tree *sub_tree = NULL;

  guint8 packettype, flags, negotype;
  guint16 msgtype16, netmsgtype;
  guint32 packetlen, netmsgtype32;
  char *str;
  guint slen;
  const value_string *msgtypes = NULL;

  islive = TRUE;

  if (tree) { /* we are being asked for details */
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_urulive, etvb, 0, -1, TRUE);
    uru_tree = proto_item_add_subtree(ti, ett_urulive);
  }

  if (live_conv->is_encrypted
      && ((isclient && live_conv->c2s_crypt_zero <= seq)
	  || (!isclient && live_conv->s2c_crypt_zero <= seq))) {
    guint8 *newbuf;
    guint32 port;
    struct rc4_key *key;
    int len;

    port = (isclient ? pinfo->srcport : pinfo->destport);
    key = find_rc4_key(port);
    len = tvb_length_remaining(etvb, offset);
    if (!global_urulive_decrypt || !key
	|| (isclient && live_conv->c2s_next_state.seq == 0)
	|| (!isclient && live_conv->s2c_next_state.seq == 0)) {
      /* we can't decrypt this */
      proto_tree_add_item(uru_tree, hf_urulive_encrypted, etvb, offset, 
			  len, FALSE);
      return;
    }
    newbuf = tvb_memdup(etvb, offset, len);
    urulive_decrypt(seq, TRUE, newbuf, len);
    tvb = tvb_new_real_data(newbuf, len, len);
    tvb_set_child_real_data_tvbuff(etvb, tvb);
    tvb_set_free_cb(tvb, g_free);
    add_new_data_source(pinfo, tvb, "Decrypted Data");
    offset = 0;
  }
  else {
    tvb = etvb;
  }

  packettype = tvb_get_guint8(tvb, offset);
  flags = tvb_get_guint8(tvb, offset+1);

    /* Unfortunately, the protocol is very different when speaking to a data
       server. After the first negotiation message from the client to the
       server, *all* other messages are started by a four-byte message
       length. This is different than everything else, where we have the
       type and flags/length as two bytes up front.

       The only way to properly resolve this is to keep track of which
       conversations are with the data server. This means we must either have
       sniffed the initial packet in the conversation or we must have some
       other way to know which protocol applies (e.g. IP address), which would
       have to be configured by the user. We can collect up some cases by
       fancy footwork, noticing messages that appear to be of type 0x0c and
       aren't followed by any data in that packet, stuff like that, but it's
       far from guaranteed to catch cases that matter before the TCP
       desegmentation code goes off on a wild goose chase reassembling packets
       incorrectly. */
  if (live_conv->isdata > 0) {
    guint32 msgtype;

    if (packettype == 0x10 && flags == 0x1f) {
      goto do_nego; /* meh, this is easiest */
    }

    packetlen = tvb_get_letohl(tvb, offset);
    msgtype =  tvb_get_letohl(tvb, offset+4);

    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, " (File) %s",
		      val_to_str(msgtype, file_transactions,
				 "Unknown (0x%08x)"));
    }
    if (tree) {
      proto_tree_add_item(uru_tree, hf_urulive_file_msglen, tvb, offset,
			  4, TRUE);
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_file_trans, tvb, offset,
			  4, TRUE);
      offset += 4;

      if (msgtype == PingRequestTrans) {
	/* data server keepalives */
	proto_tree_add_item(uru_tree, hf_urulive_ping_id, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (isclient) {
	if (msgtype == FileRcvdFileManifestChunkTrans
	    || msgtype == FileRcvdFileDownloadChunkTrans) {
	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_file_unknum, tvb, offset,
			      4, TRUE);
	  offset += 4;
	}
	else if (msgtype == ManifestRequestTrans
		 || msgtype == DownloadRequestTrans) {
	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  slen = packetlen - 12;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(uru_tree,
			     (msgtype == ManifestRequestTrans
			      ? hf_urulive_file_mname
			      : hf_urulive_file_fname),
			     tvb, offset, slen, str);
	  MAYBE_FREE(str);
	  proto_tree_add_item(uru_tree, hf_urulive_file_buf, tvb,
			      offset+slen, 524-slen, FALSE);
	  offset += 524;
	}
      }
      else {
	if (msgtype == ManifestRequestTrans) {
	  guint32 remaining;
	  proto_tree *mflags_tree;

	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_file_unknum, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_file_mct, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  remaining = tvb_get_letohl(tvb, offset);
	  tf = proto_tree_add_item(uru_tree, hf_urulive_file_mlen, tvb, offset,
				   4, TRUE);
	  proto_item_append_text(tf, " (%u)", 2*remaining);
	  offset += 4;
	  remaining = 2*remaining;
	  if (remaining > 1) {
	    remaining -= 2;
	    while (remaining > 0) {
	      guint8 first_char;

	      first_char = tvb_get_guint8(tvb, offset);
	      if (first_char == '\0') {
		/* this is the end of the list */
		break;
	      }
	      slen = remaining;
	      str = get_widestring(tvb, offset, &slen);
	      tf = proto_tree_add_STR(uru_tree, hf_urulive_file_mfile, tvb,
				      offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      remaining -= slen;
	      sub_tree = proto_item_add_subtree(tf, ett_manifest);
	      slen = remaining;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(sub_tree, hf_urulive_file_mpath, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      remaining -= slen;
	      slen = remaining;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(sub_tree, hf_urulive_file_muncsum, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      remaining -= slen;
	      slen = remaining;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(sub_tree, hf_urulive_file_mcsum, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      remaining -= slen;
	      urulive_add_stringlen(sub_tree, tvb, offset,
				    hf_urulive_file_munclen);
	      offset += 6;
	      remaining -= 6;
	      urulive_add_stringlen(sub_tree, tvb, offset,
				    hf_urulive_file_mclen);
	      offset += 6;
	      remaining -= 6;
	      slen = remaining;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(sub_tree, hf_urulive_file_mterm, tvb, offset,
				 slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      remaining -= slen;
	      tf = proto_tree_add_item(sub_tree, hf_urulive_file_mflags, tvb,
				       offset, 4, TRUE);
	      mflags_tree = proto_item_add_subtree(tf, ett_mflags);
	      proto_tree_add_item(mflags_tree, hf_urulive_file_mflags_sc, tvb,
				  offset, 4, TRUE);
	      proto_tree_add_item(mflags_tree, hf_urulive_file_mflags_of, tvb,
				  offset, 4, TRUE);
	      proto_tree_add_item(mflags_tree, hf_urulive_file_mflags_sf, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	      remaining -= 4;
	    }
	    slen = tvb_length_remaining(tvb, offset);
	    if (slen > 1) {
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_file_mterm, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	    }
	  }
	}
	else if (msgtype == DownloadRequestTrans) {
	  guint32 len;

	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_file_unknum, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_file_flen, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  len = tvb_get_letohl(tvb, offset);
	  proto_tree_add_item(uru_tree, hf_urulive_file_thislen, tvb,
			      offset, 4, TRUE);
	  offset += 4;
	  if ((guint)tvb_length_remaining(tvb, offset) < len) {
	    tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					  tvb, offset,
					  tvb_length_remaining(tvb, offset), 1,
					  "Not enough data");
	    PROTO_ITEM_SET_GENERATED(tf);
	    offset += tvb_length_remaining(tvb, offset);
	  }
	  else if (len > 0) {
	    proto_tree_add_item(uru_tree, hf_urulive_file_data, tvb, offset,
				len, TRUE);
	    offset += len;
	  }
	}
      }

      goto show_unknown;
    }
    return;
  }

  if (flags) {
    /* msgflags is actually a length */
  do_nego:
    negotype = tvb_get_guint8(tvb, offset);
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, " (Negotiation) %s",
		      val_to_str(negotype, live_negotypes,
				 "Unknown (0x%02x)"));
    }
    if (negotype == NegotiateFile) {
      if (live_conv->isdata != CERTAIN_NO) {
	live_conv->isdata = CERTAIN_YES;
      }
      live_conv->negotiation_done = TRUE;
      live_conv->state_known = TRUE;
    }
    else if (negotype == NegotiateAuth) {
      if (live_conv->isdata != CERTAIN_YES) {
	live_conv->isdata = CERTAIN_NO;
      }
      if (live_conv->isgame != CERTAIN_YES) {
	live_conv->isgame = CERTAIN_NO;
      }
      if (live_conv->isgate != CERTAIN_YES) {
	live_conv->isgate = CERTAIN_NO;
      }
    }
    else if (negotype == NegotiateGame) {
      if (live_conv->isdata != CERTAIN_YES) {
	live_conv->isdata = CERTAIN_NO;
      }
      if (live_conv->isgame != CERTAIN_NO) {
	live_conv->isgame = CERTAIN_YES;
      }
      if (live_conv->isgate != CERTAIN_YES) {
	live_conv->isgate = CERTAIN_NO;
      }
    }
    else if (negotype == NegotiateGate) {
      if (live_conv->isdata != CERTAIN_YES) {
	live_conv->isdata = CERTAIN_NO;
      }
      if (live_conv->isgame != CERTAIN_YES) {
	live_conv->isgame = CERTAIN_NO;
      }
      if (live_conv->isgate != CERTAIN_NO) {
	live_conv->isgate = CERTAIN_YES;
      }
      /* this connection type was added for MOULagain */
      live_conv->ispre4 = CERTAIN_NO;
      live_conv->isv1 = CERTAIN_NO;
      live_conv->ispre9 = CERTAIN_NO;
    }
    if (tree) {
      proto_tree_add_item(uru_tree, hf_urulive_nego_type, tvb, offset,
			  1, TRUE);
      proto_tree_add_item(uru_tree, hf_urulive_nego_len, tvb, offset+1,
			  1, TRUE);
    }
    offset += 2;

    if (flags == 0x1f) {
      /* These seem to be initial negotiation messages with each server.
	 They are not encrypted. */
      guint32 datalen, version;

      version = tvb_get_letohl(tvb, offset+1);
      if (negotype != NegotiateFile) {
	if (global_urulive_detect_version) {
	 if (version >= 556) {
	  live_conv->ispre4 = CERTAIN_NO;
	  if (version >= 777) { /* 777 == Live 8 */
	    live_conv->isv1 = CERTAIN_NO;
	    if (version > 778) {
	      live_conv->ispre9 = CERTAIN_NO;
	    }
	    else {
	      live_conv->ispre9 = CERTAIN_YES;
	    }
	  }
	  else {
	    /* it does not really matter, as any traces we might have from
	       live 5-7 can't be decrypted, so it's irrelevant what the
	       contents of the messages really are; we could test the Live 5
	       version number, or use CERTAIN_YES here to the same effect */
	    live_conv->isv1 = GUESS_YES;
	    live_conv->ispre9 = GUESS_YES;
	  }
	 }
	 else if (version == 0) {
	   /* UGH! version set to zero in fan code... */
	   live_conv->ispre4 = CERTAIN_NO;
	   live_conv->isv1 = CERTAIN_NO;
	   live_conv->ispre9 = CERTAIN_NO;
	 }
	 else {
	   if (live_conv->ispre4 != CERTAIN_NO) {
	     live_conv->ispre4 = CERTAIN_YES;
	   }
	   if (live_conv->isv1 != CERTAIN_NO) {
	     live_conv->isv1 = CERTAIN_YES;
	   }
	   if (live_conv->ispre9 != CERTAIN_NO) {
	     live_conv->ispre9 = CERTAIN_YES;
	   }
	 }
	}
      }
      if (tree) {
	proto_tree_add_item(uru_tree, hf_urulive_nego_unk0, tvb, offset,
			    1, TRUE);
	offset += 1;
	proto_tree_add_item(uru_tree, hf_urulive_nego_ver, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_nego_unk32, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_nego_release, tvb, offset,
			    4, TRUE);
	offset += 4;
	tf = proto_tree_add_item(uru_tree, hf_urulive_nego_idstring, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(tf, tvb, offset);
	offset += 16;
	/* Since flags is a length, the implication is that this is not
	   a blob of data following the 0x1f message, but that blob of data
	   does not appear to match other packets with that msgtype, so... */
	datalen = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_nego_datalen, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_nego_data, tvb, offset,
			    datalen-4, TRUE);
	offset += datalen-4;
      }
    }
    else if (flags == 0x42) {
      if (tree) {
	/* This appears to be a separate message from the "negotiation". */
	proto_tree_add_item(uru_tree, hf_urulive_nego_nonce, tvb, offset,
			    64, TRUE);
      }
#ifdef HAVE_LIBGCRYPT
      if (global_urulive_use_private_keys && global_urulive_decrypt) {
	/* compute the cilent's half of the key and store it */
	guint8 be[64];
	gcry_mpi_t mod, exp;
	if (live_conv->isgame < 0 && live_conv->isgate < 0) {
	  mod = auth_modulus;
	  exp = auth_exponent;
	}
	else {
	  /* game and gate */
	  mod = game_modulus;
	  exp = game_exponent;
	}
	if (mod && exp && tvb_length_remaining(tvb, offset) >= 64) {
	  /* we do have the key; proceed */
	  int i;
	  gcry_mpi_t base = NULL, result = NULL;
	  tvb_memcpy(tvb, be, offset, 64);
	  /* swap from little-endian to big-endian */
	  for (i = 0; i < 32; i++) {
	    be[i] ^= be[63-i];
	    be[63-i] ^= be[i];
	    be[i] ^= be[63-i];
	  }
	  if (!gcry_mpi_scan(&base, GCRYMPI_FMT_USG, be, 64, NULL)) {
	    /* compute be ^ exp */
	    result = gcry_mpi_new(64*8);
	    gcry_mpi_powm(result, base, exp, mod);
	    /* save the first 7 little-endian bytes,
	       which is the last 7 big-endian bytes */
	    if (!gcry_mpi_print(GCRYMPI_FMT_USG, be, 64, NULL, result)) {
	      live_conv->key_half[0] = 1;
	      for (i = 1; i < 8; i++) {
		live_conv->key_half[i] = be[64-i];
	      }
	    }
	  }
	  gcry_mpi_release(base);
	  gcry_mpi_release(result);
	}
      }
#endif
      offset += 64;
    }
    else if (flags == 0x09) {
      /* response to the nonce */
      if (!live_conv->negotiation_done) {
#ifdef HAVE_LIBGCRYPT
	if (global_urulive_use_private_keys) {
	  /* the value passed to find_rc4_key does not really matter */
	  struct rc4_key *special_key = find_rc4_key(0xffffffff);
	  if (!special_key) {
	    /* this should not happen, but it could under memory duress */
	  }
	  else {
	    guint i;

	    if (live_conv->key_half[0]) {
	      /* requested using private keys, and we do have the data */
	      memcpy(special_key->key, live_conv->key_half+1, 7);
	    }
	    for (i = 0; i < 7; i++) {
	      special_key->key[i] ^= tvb_get_guint8(tvb, offset+i);
	    }
	  }
	}
#endif
	urulive_setup_crypto(seq+2+tvb_length_remaining(tvb, offset),
			     pinfo->destport);
	live_conv->negotiation_done = TRUE;
      }
      if (tree) {
	proto_tree_add_item(uru_tree, hf_urulive_nego_reply, tvb, offset,
			    7, TRUE);
	offset += 7;
      }
    }

    if (tree) {
      goto show_unknown;
    }
    else {
      return;
    }
  }

  /* here, we have a two-byte message code after all */
  msgtype16 = tvb_get_letohs(tvb, offset);

  if (isclient) {
    if (live_conv->isv1 > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_client_v1, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_client_msgtypes_v1;
    }
    else if (live_conv->isgame > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_game_client, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_client_game_msgtypes;
    }
    else if (live_conv->isgate > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_gate_client, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_client_gate_msgtypes;
    }
    else {
      if (live_conv->ispre9 > 0
	  && msgtype16 >= kCli2Auth_SendFriendInviteRequest) {
	if (tree) {
	  tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_auth_client8,
				   tvb, offset, 2, TRUE);
	}
	msgtypes = live_client_auth_msgtypes8;
      }
      else {
	if (tree) {
	  tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_auth_client,
				   tvb, offset, 2, TRUE);
	}
	msgtypes = live_client_auth_msgtypes;
      }
    }
  }
  else {
    if (live_conv->isv1 > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_server_v1, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_server_msgtypes_v1;
    }
    else if (live_conv->isgame > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_game_server, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_server_game_msgtypes;
    }
    else if (live_conv->isgate > 0) {
      if (tree) {
	tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_gate_server, tvb,
				 offset, 2, TRUE);
      }
      msgtypes = live_server_gate_msgtypes;
    }
    else {
      if (live_conv->ispre9 > 0
	  && msgtype16 >= kAuth2Cli_SendFriendInviteReply) {
	if (tree) {
	  tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_auth_server8,
				   tvb, offset, 2, TRUE);
	}
	msgtypes = live_server_auth_msgtypes8;
      }
      else {
	if (tree) {
	  tf = proto_tree_add_item(uru_tree, hf_urulive_msgtype_auth_server,
				   tvb, offset, 2, TRUE);
	}
	msgtypes = live_server_auth_msgtypes;
      }
    }
  }
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
		    val_to_str(msgtype16, msgtypes, "Unknown (0x%04x)"));
  }
  if (live_conv->isv1 > 0) {
    msgtype16 = get_v2_value(msgtype16);
  }
  else {
    msgtype16 = get_9_value(msgtype16, live_conv->ispre9);
  }
  offset += 2;

  if (msgtype16 == kCli2Auth_PingRequest) {
    if (tree) {
      /* auth, game server keepalives */
      proto_tree_add_item(uru_tree, hf_urulive_ping_id, tvb, offset,
			  4, TRUE);
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_ping_unk1, tvb, offset,
			  4, TRUE);
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_ping_unk2, tvb, offset,
			  4, TRUE);
      offset += 4;
    }
  }
  else if (live_conv->isgame > 0 && msgtype16 == kCli2Game_PropagateBuffer) {
    /* game server<->client */
    if (tree) {
      gint parsed;

      netmsgtype32 = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(uru_tree, hf_urulive_cmd, tvb, offset, 4, TRUE);
      offset += 4;
      packetlen = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(uru_tree, hf_urulive_msglen, tvb, offset, 4, TRUE);
      offset += 4;

      netmsgtype = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(uru_tree, hf_urulive_cmd2, tvb, offset, 2, TRUE);
      offset += 2;
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
			val_to_str(netmsgtype, live_typecodes,
				   "Unknown (0x%02x)"));
      }
      offset = dissect_netmsg_flags(tvb, offset, uru_tree);
      if (tvb_length_remaining(tvb, offset) > 0) {
	tf = proto_tree_add_item(uru_tree, hf_uru_msgbody, tvb, offset,
				 -1, TRUE);
	sub_tree = proto_item_add_subtree(tf, ett_netmsg);
	netmsgtype = live_translate(netmsgtype);
	parsed = dissect_plNetMessage(netmsgtype, tvb, offset,
				      sub_tree, pinfo);
	if (parsed > 0) {
	  offset = parsed;
	}
      }
    }
  }
  else if (live_conv->isgame > 0 && msgtype16 == kGame2Cli_GameMgrMsg) {
    guint32 msgtype, reqid, gameid, unk32;
    guint i;
    gboolean setup = FALSE;
    enum game_types gametype = Unknown_pfGmType;
    char *clothorder;
    int msgtypes = -1;

    if (tree) {
      proto_tree_add_item(uru_tree, hf_urulive_msglen, tvb, offset, 4, TRUE);
    }
    offset += 4;
    msgtype = tvb_get_letohl(tvb, offset);
    reqid = tvb_get_letohl(tvb, offset + 4);
    gameid = tvb_get_letohl(tvb, offset + 8);
    if (gameid != 0) {
      gametype = (enum game_types)se_tree_lookup32(gameIDmap, gameid);
    }
    if (reqid != 0) {
      setup = TRUE;
    }
    if (tree) {
      if (setup) {
	msgtypes = hf_urulive_gamemgr_msgtype;
      }
      else if ((isclient && msgtype <= 2)
	       || (!isclient && msgtype <= kGameCliOwnerChangeMsg)
	       || gametype == Unknown_pfGmType) {
	msgtypes = hf_urulive_gamemgr_gameclimsg;
      }
      else if (gametype == pfGmBlueSpiral) {
	if (isclient) {
	  msgtypes = hf_urulive_gamemgr_clispiralmsg;
	}
	else {
	  msgtypes = hf_urulive_gamemgr_spiralmsg;
	}
      }
      else if (gametype == pfGmHeek) {
	if (isclient) {
	  msgtypes = hf_urulive_gamemgr_cliheekmsg;
	}
	else {
	  msgtypes = hf_urulive_gamemgr_heekmsg;
	}
      }
      else if (gametype == pfGmMarker) {
	if (isclient) {
	  msgtypes = hf_urulive_gamemgr_climarkermsg;
	}
	else {
	  msgtypes = hf_urulive_gamemgr_markermsg;
	}
      }
      else if (gametype == pfGmClimbingWall) {
	msgtypes = hf_urulive_gamemgr_climbingwallmsg;
      }
      else if (gametype == pfGmVarSync) { /* only quabs currently */
	if (isclient) {
	  msgtypes = hf_urulive_gamemgr_clivarsyncmsg;
	}
	else {
	  msgtypes = hf_urulive_gamemgr_varsyncmsg;
	}
      }
      if (msgtypes != -1) {
	proto_tree_add_item(uru_tree, msgtypes, tvb, offset, 4, TRUE);
      }
      else {
	tf = proto_tree_add_boolean_format(uru_tree,
					   hf_uru_incomplete_dissection,
					   tvb, offset, 4, 1,
					   "Incomplete addition of game type");
	PROTO_ITEM_SET_GENERATED(tf);
      }
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_reqid, tvb,
			  offset, 4, TRUE);
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_gameid, tvb,
			  offset, 4, TRUE);
      offset += 4;
      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_len, tvb,
			  offset, 4, TRUE);
      offset += 4;
    }
    else {
      offset += 16;
    }

    if (setup) {
      if (tree) {
	proto_item_append_text(uru_tree, " (Game Setup)");
      }
      if (!isclient || msgtype == 1) {
	/* these fields are not in the client's marker game requests (sigh) */
	if (tree) {
	  unk32 = tvb_get_letohl(tvb, offset);
	  proto_tree_add_item(uru_tree, hf_urulive_gamemgr_unk0, tvb,
			      offset, 4, TRUE);
	  /* XXX unk0 is 0xff for VarSync */
	  proto_tree_add_item(uru_tree, hf_urulive_gamemgr_clientid, tvb,
			      offset+4, 4, TRUE);
	}
	offset += 8;
      }
      if (tree) {
	ti = proto_tree_add_item(uru_tree, hf_urulive_gamemgr_uuid, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
      }

      /* the game type is expressed by the UUID;
	 the first four bytes are plenty distinct */
      gametype = (enum game_types)tvb_get_letohl(tvb, offset);
      if (gametype == pfGmMarker || gametype == pfGmHeek
	  || gametype == pfGmBlueSpiral || gametype == pfGmVarSync) {
	if (!isclient) {
	  /* inserting integers (non-pointers) works because the
	     guts of the tree are not freed, they are assumed to be
	     freed all at once by the se_mem cleanup */
	  gameid = tvb_get_letohl(tvb, offset + 16);
	  se_tree_insert32(gameIDmap, gameid, (void *)gametype);
	}
	if (tree) {
	  proto_item_append_text(ti, " (%s)",
				 val_to_str(gametype, gamemgr_uuids,
					    "UNKNOWN"));
	}
      }
      else if (tree) {
	proto_tree_add_boolean_format(uru_tree,
				      hf_uru_incomplete_dissection,
				      tvb, offset, 16, 1,
				      "Unrecognized game type");
      }

      if (tree) {
	offset += 16;
	proto_tree_add_item(uru_tree, hf_urulive_gamemgr_idresult, tvb,
			    offset, 4, TRUE);
	offset += 4;

	if (isclient) {
	  if (gametype == pfGmBlueSpiral) {
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_extra, tvb,
				offset, 1, TRUE);
	    offset += 1;
	  }
	  else if (gametype == pfGmMarker) {
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_timelimit, tvb,
				offset, 4, TRUE);
	    offset += 4;
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_gametype,
				tvb, offset, 1, TRUE);
	    offset += 1;
	    slen = 516;
	    str = get_widestring(tvb, offset, &slen);
	    proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_name, tvb,
			       offset, slen, str);
	    MAYBE_FREE(str);
	    offset += slen;
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				offset, 516-slen, FALSE);
	    offset += 516 - slen;
	    slen = 160;
	    str = get_widestring(tvb, offset, &slen);
	    proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_template, tvb,
			       offset, slen, str);
	    MAYBE_FREE(str);
	    offset += slen;
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				offset, 160-slen, FALSE);
	    offset += 160 - slen;
	  }
	  else if (gametype == pfGmVarSync) {
	    proto_tree_add_item(uru_tree, hf_urulive_gamemgr_extra, tvb,
				offset, 1, TRUE);
	    offset += 1;
	  }
	}
      }
    }
    else { /* not setup packets - let us try to type and dissect */
      if (tree) {
	/* hide setup request ID */
	PROTO_ITEM_SET_HIDDEN(ti);
	if (!isclient && msgtype <= kGameCliOwnerChangeMsg) {
	  /* join/leave and owner messages */
	  proto_tree_add_item(uru_tree, hf_urulive_gamemgr_clientid, tvb,
			      offset, 4, TRUE);
	  offset += 4;
	}
	else if (gametype == pfGmBlueSpiral) {
	    if (msgtype == kBlueSpiralClothHit && isclient) {
		proto_tree_add_item(uru_tree, hf_urulive_gamemgr_cloth, tvb,
				    offset, 1, TRUE);
		offset += 1;
	    }
	    else if (msgtype == kBlueSpiralClothOrder && !isclient) {
		clothorder = tvb_bytes_to_str_punct(tvb, offset, 7, 0x20);
		tf = proto_tree_add_item(uru_tree,
					 hf_urulive_gamemgr_clothorder,
					 tvb, offset, 7, TRUE);
		offset += 7;
		for (i = 0; i < 7; i++) {
		  clothorder[(i*2)] = clothorder[(i*3)+1];
		  clothorder[(i*2)+1] = ' ';
		}
		clothorder[(i*2)-1] = '\0';
		proto_item_append_text(tf, " (%s)", clothorder);
	    }
	    else if (msgtype == kBlueSpiralGameStarted && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_rotate, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	}
	else if (gametype == pfGmHeek) {
	    if (msgtype == kHeekPlayGameReq && isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_position, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_score_value, tvb, offset,
				  4, TRUE);
	      offset += 4;
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_plist_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	    }
	    else if (msgtype == kHeekChoice && isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_choice, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekAnimationFinished && isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_seq, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekWelcome && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_score, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_rank, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_plist_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	    }
	    else if (msgtype == kHeekInterfaceState && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_ifacestate, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekCountdownState && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_countdown, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekGameWin && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_choice, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekPointUpdate && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_update, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_score, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_rank, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	    }
	    else if (msgtype == kHeekWinLose && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_win, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_choice, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekPlayGame && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_playing, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_single, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_enable, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekLightState && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_light, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_state, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if (msgtype == kHeekDrop && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_position, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	}
	else if (gametype == pfGmMarker) {
	    if (msgtype == kMarkerTemplateCreated && !isclient) {
	      slen = 160;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_template, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 160-slen, FALSE);
	      offset += 160 - slen;
	    }
	    else if (msgtype == kMarkerGameType && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_gametype,
				  tvb, offset, 1, TRUE);
	      offset += 1;
	    }
	    else if ((msgtype == kMarkerGameNameChanged && !isclient) ||
		     (msgtype == kMarkerGameNameChange && isclient)) {
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	    }
	    else if (msgtype == kMarkerTeamAssigned && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_team, tvb,
				  offset, 1, TRUE);
	      offset += 1;
	    }
	    else if ((msgtype == kMarkerMarkerAdded && !isclient) ||
		     (msgtype == kMarkerMarkerAdd && isclient)) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markerposx,
				  tvb, offset, 8, TRUE);
	      offset += 8;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markerposy,
				  tvb, offset, 8, TRUE);
	      offset += 8;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markerposz,
				  tvb, offset, 8, TRUE);
	      offset += 8;
	      if (!isclient) {
		proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markernum,
				     tvb, offset, 4, TRUE);
		offset += 4;
	      }
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	      slen = 160;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_age_fname, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 160-slen, FALSE);
	      offset += 160 - slen;
	    }
	    else if ((msgtype == kMarkerMarkerNameChanged && !isclient) ||
		     (msgtype == kMarkerMarkerNameChange && isclient)) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markernum,
				   tvb, offset, 4, TRUE);
	      offset += 4;
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	    }
	    else if ((msgtype == kMarkerMarkerCaptured && !isclient) ||
		     (msgtype == kMarkerMarkerCapture && isclient)) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markernum,
				  tvb, offset, 4, TRUE);
	      offset += 4;
	      if (!isclient) {
		proto_tree_add_item(uru_tree, hf_urulive_gamemgr_captured,
				    tvb, offset, 1, TRUE);
		offset += 1;
	      }
	    }
	    else if (msgtype == kMarkerGamePaused && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_gametime,
				  tvb, offset, 4, TRUE);
	      offset += 4;
	    }
	    else if ((msgtype == kMarkerMarkerDeleted && !isclient) ||
		     (msgtype == kMarkerMarkerDelete && isclient)) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markernum,
				  tvb, offset, 4, TRUE);
	      offset += 4;
	    }
	    else if (msgtype == kMarkerGameDeleted && !isclient) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_markerdel,
				  tvb, offset, 1, TRUE);
	      offset += 1;
	    }
	}
	else if (gametype == pfGmClimbingWall) {
	    /* XXX to do when we actually have some packets from this game */
	}
	else if (gametype == pfGmVarSync) { /* only quabs currently */
	    if ((msgtype == kVarSyncNumericVarCreated && !isclient) ||
		(msgtype == kVarSyncNumericVarCreate && isclient)) {
	      slen = 512;
	      str = get_widestring(tvb, offset, &slen);
	      proto_tree_add_STR(uru_tree, hf_urulive_gamemgr_name, tvb,
				 offset, slen, str);
	      MAYBE_FREE(str);
	      offset += slen;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_buf, tvb,
				  offset, 512-slen, FALSE);
	      offset += 512 - slen;
	      if (!isclient) {
		proto_tree_add_item(uru_tree, hf_urulive_gamemgr_id, tvb,
				    offset, 4, TRUE);
		offset += 4;
	      }
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_value, tvb,
				  offset, 8, TRUE);
	      offset += 8;
	    }
	    else if ((msgtype == kVarSyncNumericVarChanged && !isclient) ||
		     (msgtype == kVarSyncNumericVarChange && isclient)) {
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_id, tvb,
				  offset, 4, TRUE);
	      offset += 4;
	      proto_tree_add_item(uru_tree, hf_urulive_gamemgr_value, tvb,
				  offset, 8, TRUE);
	      offset += 8;
	    }
	}
      }
    }
  }
  else if (isclient) {
    if (tree) {
      if (live_conv->isgate > 0) {
	/* assuming file and auth requests are the same */
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset, 4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_gate_unk0, tvb, offset,
			    1, TRUE);
	offset += 1;
      }
      else if (live_conv->isgame < 0 &&
	       msgtype16 == kCli2Auth_ClientRegisterRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_register_ver, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_AgeRequest) {
        proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
        offset += 4;
        str = get_uru_widestring(tvb, offset, &slen);
        proto_tree_add_STR(uru_tree, hf_urulive_age_fname, tvb, offset,
			   slen, str);
        MAYBE_FREE(str);
	offset += slen;
        ti = proto_tree_add_item(uru_tree, hf_urulive_age_UUID, tvb, offset,
			    16, TRUE);
	append_uru_uuid(ti, tvb, offset);
        offset += 16;
      }
      else if (live_conv->isgame < 0
	       && msgtype16 == kCli2Auth_AcctLoginRequest) {
	guint32 hash1, hash2, hash3, hash4, hash5;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_login_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_login_name, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
	hash1 = tvb_get_letohl(tvb, offset);
	hash2 = tvb_get_letohl(tvb, offset+4);
	hash3 = tvb_get_letohl(tvb, offset+8);
	hash4 = tvb_get_letohl(tvb, offset+12);
	hash5 = tvb_get_letohl(tvb, offset+16);
	proto_tree_add_bytes_format_value(uru_tree, hf_urulive_login_hash,
					  tvb, offset, 20,
					  tvb_get_ptr(tvb, offset, 20),
					  "%08x %08x %08x %08x %08x",
					  hash1, hash2, hash3, hash4, hash5);
	offset += 20;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_login_token, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_login_os, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_FileListRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb,
			    offset, 4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_file_list_dir, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_file_list_suffix, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_FileDownloadRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb,
			    offset, 4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_file_get_file, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_FileDownloadChunkAck) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb,
			    offset, 4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_AcctSetPlayerRequest
	       || msgtype16 ==  kCli2Auth_PlayerDeleteRequest
	       || msgtype16 == kCli2Auth_UpgradeVisitorRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_player, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_SendFriendInviteRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_friend_uuid, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_friend_addr, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_friend_type, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_VaultFetchNodeRefs) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_VaultNodeFind) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_len, tvb, offset,
			    4, TRUE);
	offset += 4;
	offset = add_live_vault_node(tvb, offset, uru_tree);
      }
      else if (msgtype16 == kCli2Auth_VaultNodeFetch) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_VaultNodeCreate) {
	guint32 sroffset;
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_len, tvb, offset,
			    4, TRUE);
	offset += 4;
	sroffset = add_live_vault_node(tvb, offset, uru_tree);
	offset = sroffset;
      }
      else if (msgtype16 == kCli2Auth_VaultNodeAdd) {
	if (live_conv->ispre4 < 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	}
	proto_tree_add_item(uru_tree, hf_urulive_vault_parent, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_child, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_owner, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_VaultNodeSave) {
	guint32 sroffset;
	if (live_conv->ispre4 < 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	}
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	/* this UUID is used to correlate a save to the server with a changed
	   from the server; in other words, it's a global reqid */
	ti = proto_tree_add_item(uru_tree, hf_urulive_vault_globalreqid,
				 tvb, offset, 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
	proto_tree_add_item(uru_tree, hf_urulive_vault_len, tvb, offset,
			    4, TRUE);
	offset += 4;
	sroffset = add_live_vault_node(tvb, offset, uru_tree);
	offset = sroffset;
      }
      else if (msgtype16 == kCli2Auth_VaultNodeRemove) {
	if (live_conv->ispre4 < 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			      4, TRUE);
	  offset += 4;
	}
	proto_tree_add_item(uru_tree, hf_urulive_vault_parent, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_child, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_VaultInitAgeRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	tf = proto_tree_add_item(uru_tree, hf_urulive_vault_createageuuid, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(tf, tvb, offset);
	offset += 16;
	tf = proto_tree_add_item(uru_tree, hf_urulive_age_parentid, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(tf, tvb, offset);
	offset += 16;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_age_fname, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_age_iname, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_age_uname, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_age_dname, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	proto_tree_add_item(uru_tree, hf_urulive_age_unk1, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_VaultSendNode) {
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_player, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_PlayerCreateRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_create_name, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_create_gender, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_create_code, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_GetPublicAgeList) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_uru_age_fname, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kCli2Auth_SetAgePublic) {
	proto_tree_add_item(uru_tree, hf_urulive_age_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_public, tvb, offset,
			    1, TRUE);
	offset += 1;
      }
      else if (msgtype16 == kCli2Auth_ScoreGetScores
	       || msgtype16 == kCli2Auth_ScoreCreate) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_holder, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_score_name, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
	if (msgtype16 == kCli2Auth_ScoreCreate) {
	  proto_tree_add_item(uru_tree, hf_urulive_score_type, tvb,
			      offset, 4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_score_value, tvb,
			      offset, 4, TRUE);
	  offset += 4;
	}
      }
      else if (msgtype16 == kCli2Auth_ScoreAddPoints) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_id, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_add, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_ScoreTransferPoints) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_id, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_dest, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_value, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kCli2Auth_AcctChangePasswordRequest) {
	guint32 hash1, hash2, hash3, hash4, hash5;	  
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_login_name, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
	hash1 = tvb_get_letohl(tvb, offset);
	hash2 = tvb_get_letohl(tvb, offset+4);
	hash3 = tvb_get_letohl(tvb, offset+8);
	hash4 = tvb_get_letohl(tvb, offset+12);
	hash5 = tvb_get_letohl(tvb, offset+16);
	proto_tree_add_bytes_format_value(uru_tree, hf_urulive_login_hash,
					  tvb, offset, 20,
					  tvb_get_ptr(tvb, offset, 20),
					  "%08x %08x %08x %08x %08x",
					  hash1, hash2, hash3, hash4, hash5);
	offset += 20;
      }
      else if (msgtype16 == kCli2Auth_LogPythonTraceback
	       || msgtype16 == kCli2Auth_LogStackDump
	       || msgtype16 == kCli2Auth_LogClientDebuggerConnect) {
	str = get_uru_widestring(tvb, offset, &slen);
	/* XXX make new lines where there are newlines in the string :) */
	proto_tree_add_STR(uru_tree, hf_urulive_log_python, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (live_conv->isgame > 0
	       && msgtype16 == kCli2Game_JoinAgeRequest) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_id, tvb, offset,
			    4, TRUE);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_login_acct, tvb, offset,
			    16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
	proto_tree_add_item(uru_tree, hf_urulive_vault_player, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else {
	tf = proto_tree_add_boolean(uru_tree, hf_uru_incomplete_dissection,
				    tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(tf);
      }
    }
  }
  else {
    if (tree) {
      if (live_conv->isgate > 0) {
	/* assuming file and auth replies are the same */
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset, 4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_gate_addr, tvb, offset,
			   slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (live_conv->isgame < 0
	       && msgtype16 == kAuth2Cli_ClientRegisterReply) {
	proto_tree_add_item(uru_tree, hf_urulive_register_reply, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (live_conv->isgame < 0
	       && msgtype16 == kAuth2Cli_ServerAddr) {
	proto_tree_add_item(uru_tree, hf_urulive_addr_ip, tvb, offset,
			    4, TRUE);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_addr_uuid, tvb, offset,
				 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
      }
      else if (msgtype16 == kAuth2Cli_AgeReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_unk1, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_id, tvb, offset,
			    4, TRUE);
	offset += 4;

	ti = proto_tree_add_item(uru_tree, hf_urulive_age_UUID, tvb, offset,
			    16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
	proto_tree_add_item(uru_tree, hf_urulive_age_nodeid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_addr, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_AcctLoginReply) {
	guint32 key1, key2, key3, key4;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_login_acct, tvb,
				 offset, 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
	proto_tree_add_item(uru_tree, hf_urulive_login_unk8, tvb, offset,
			    4, TRUE);
	offset += 4;
	/* this appears to actually be a bitfield: bit 0: trial/visitor,
	   bit 1: unknown (1 in MOUL) */
	proto_tree_add_item(uru_tree, hf_urulive_login_flags, tvb, offset,
			    4, TRUE);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_login_key, tvb,
				 offset, 16, TRUE);
	key1 = tvb_get_letohl(tvb, offset);
	key2 = tvb_get_letohl(tvb, offset+4);
	key3 = tvb_get_letohl(tvb, offset+8);
	key4 = tvb_get_letohl(tvb, offset+12);
	proto_item_append_text(ti," (0x%08x 0x%08x 0x%08x 0x%08x)",
			       key1, key2, key3, key4);
	offset += 16;
      }
      else if (msgtype16 == kAuth2Cli_AcctPlayerInfo) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_plist_ki, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_plist_name, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_plist_gender, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	proto_tree_add_item(uru_tree, hf_urulive_plist_type, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_FileListReply) {
	guint32 len;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb,
			    offset, 4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_file_unk0, tvb,
			    offset, 4, TRUE);
	offset += 4;
	len = (tvb_get_letohl(tvb, offset) * 2) - 2;
	proto_tree_add_item(uru_tree, hf_urulive_file_list_len, tvb,
			    offset, 4, TRUE);
	offset += 4;
	while (len > 0) {
	  guint8 first_char;
	  guint16 upper, lower;
	  guint32 flen;

	  first_char = tvb_get_guint8(tvb, offset);
	  if (first_char == '\0') {
	    /* this is the end of the list */
	    break;
	  }
	  slen = len - 6;
	  str = get_widestring(tvb, offset, &slen);
	  upper = tvb_get_letohs(tvb, offset+slen);
	  lower = tvb_get_letohs(tvb, offset+slen+2);
	  flen = (upper << 16) | lower; /* okay, weeeeeeird */
	  proto_tree_add_bytes_format_value(uru_tree,
					    hf_urulive_file_list_file, tvb,
					    offset, slen+6, (guint8*)str,
					    "name: %s len: %u",
					    str, flen);
	  /* for packet filters */
	  tf = proto_tree_add_STR(uru_tree, hf_urulive_file_list_fname, tvb,
				  offset, slen, str);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  MAYBE_FREE(str);
	  offset += slen;
	  tf = urulive_add_stringlen(uru_tree, tvb, offset, 
				     hf_urulive_file_list_flen);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 6;
	  len -= slen + 6;
	}
	slen = tvb_length_remaining(tvb, offset);
	str = get_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_file_mterm, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kAuth2Cli_FileDownloadChunk) {
	guint32 len;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb,
			    offset, 4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_file_unk0, tvb,
			    offset, 4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_file_get_len, tvb,
			    offset, 4, TRUE);
	offset += 4;
	if (live_conv->ispre4 < 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_file_get_offset, tvb,
			      offset, 4, TRUE);
	  offset += 4;
	}
	len = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_file_get_thislen, tvb,
			    offset, 4, TRUE);
	offset += 4;
	if ((guint)tvb_length_remaining(tvb, offset) < len) {
	  tf = proto_tree_add_boolean_format(tree, hf_uru_dissection_error,
					tvb, offset,
					tvb_length_remaining(tvb, offset), 1,
					"Not enough data");
	  PROTO_ITEM_SET_GENERATED(tf);
	  offset += tvb_length_remaining(tvb, offset);
	}
	else if (len > 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_file_get_data, tvb,
			      offset, len, TRUE);
	  offset += len;
	}
      }
      else if (msgtype16 == kAuth2Cli_AcctSetPlayerReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeRefsFetched) {
	guint32 count, i;
	proto_tree *sub_tree;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	count = tvb_get_letohl(tvb, offset);
	tf = proto_tree_add_item(uru_tree, hf_urulive_vault_itemct, tvb,
				 offset, 4, TRUE);
	offset += 4;
	sub_tree = proto_item_add_subtree(tf, ett_vault_reflist);
	for (i = 0; i < count; i++) {
	  guint32 id1, id2, id3;
	  guint8 f;

	  id1 = tvb_get_letohl(tvb, offset);
	  id2 = tvb_get_letohl(tvb, offset+4);
	  id3 = tvb_get_letohl(tvb, offset+8);
	  f = tvb_get_guint8(tvb, offset+12);
	  proto_tree_add_bytes_format(sub_tree,
				      hf_urulive_vault_ref, tvb, offset,
				      13, tvb_get_ptr(tvb, offset, 13),
				      "%u->%u (%u) flag: 0x%02x",
				      id1, id2, id3, f);
	  tf = proto_tree_add_item(uru_tree, hf_uru_vault_ref_id1, tvb,
				   offset, 4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 4;
	  tf = proto_tree_add_item(uru_tree, hf_uru_vault_ref_id2, tvb,
				   offset, 4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 4;
	  tf = proto_tree_add_item(uru_tree, hf_uru_vault_ref_id3, tvb,
				   offset, 4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 4;
	  tf = proto_tree_add_item(uru_tree, hf_uru_vault_ref_flag, tvb,
				   offset, 1, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 1;
	}
      }
      else if (msgtype16 == kAuth2Cli_VaultInitAgeReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_mgr, tvb, offset,
			    4, TRUE); /* KVnodeMgrAgeNode */
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_age_info, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeFindReply) {
	guint32 count, i;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_vault_itemct, tvb, offset,
			    4, TRUE);
	offset += 4;
	for (i = 0; i < count; i++) {
	  proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			      4, TRUE);
	  tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				   4, TRUE);
	  PROTO_ITEM_SET_HIDDEN(tf);
	  offset += 4;
	}
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeFetched) {
	guint32 nlen, sroffset;
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	nlen = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_vault_len, tvb, offset,
			    4, TRUE);
	offset += 4;
	if (nlen > 0) {
	  sroffset = add_live_vault_node(tvb, offset, uru_tree);
	  offset = sroffset;
	}
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeCreated) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeAdded) {
	proto_tree_add_item(uru_tree, hf_urulive_vault_parent, tvb, offset,
        		  4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_child, tvb, offset,
        		  4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_owner, tvb,
			  offset, 4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeChanged) {
	proto_tree_add_item(uru_tree, hf_urulive_vault_nodeid, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	ti = proto_tree_add_item(uru_tree, hf_urulive_vault_globalreqid,
				 tvb, offset, 16, TRUE);
	append_uru_uuid(ti, tvb, offset);
	offset += 16;
      }
      else if (msgtype16 == kAuth2Cli_VaultNodeRemoved) {
	proto_tree_add_item(uru_tree, hf_urulive_vault_parent, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_child, tvb, offset,
			    4, TRUE);
	tf = proto_tree_add_item(uru_tree, hf_uru_node_trackid, tvb, offset,
				 4, TRUE);
	PROTO_ITEM_SET_HIDDEN(tf);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_VaultSaveNodeReply
	       || msgtype16 == kAuth2Cli_VaultAddNodeReply
	       || msgtype16 == kAuth2Cli_VaultRemoveNodeReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_PlayerCreateReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_player, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_plist_type, tvb, offset,
			    4, TRUE);
	offset += 4;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_create_name, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
	str = get_uru_widestring(tvb, offset, &slen);
	proto_tree_add_STR(uru_tree, hf_urulive_create_gender, tvb,
			   offset, slen, str);
	MAYBE_FREE(str);
	offset += slen;
      }
      else if (msgtype16 == kAuth2Cli_PlayerDeleteReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_vault_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_SendFriendInviteReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_PublicAgeList) {
	guint32 count, i, val;
	proto_tree *sub_tree;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_pubage_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_pubage_ct, tvb, offset,
			    4, TRUE);
	offset += 4;
	for (i = 0; i < count; i++) { /* 2464 bytes */
	  ti = proto_tree_add_text(uru_tree, tvb, offset, 2464, "(unknown)");
	  sub_tree = proto_item_add_subtree(ti, ett_agelist);
	  tf = proto_tree_add_item(sub_tree, hf_urulive_age_UUID, tvb,
				   offset, 16, TRUE);
	  append_uru_uuid(tf, tvb, offset);
	  offset += 16;
	  slen = 128;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(sub_tree, hf_urulive_age_fname, tvb, offset,
			     slen, str);
	  MAYBE_FREE(str);
	  offset += 128;
	  slen = 128;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(sub_tree, hf_urulive_age_iname, tvb, offset,
			     slen, str);
	  if (str && str[0] != '\0') {
	    proto_item_set_text(ti, "%s", str);
	  }
	  MAYBE_FREE(str);
	  offset += 128;
	  slen = 128;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(sub_tree, hf_urulive_age_uname, tvb, offset,
			     slen, str);
	  if (str && str[0] != '\0') {
	    proto_item_set_text(ti, "%s", str);
	  }
	  MAYBE_FREE(str);
	  offset += 128;
	  slen = 128;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(sub_tree, hf_urulive_age_dname, tvb, offset,
			     slen, str);
	  if (str && str[0] != '\0') {
	    proto_item_set_text(ti, "%s", str);
	  }
	  MAYBE_FREE(str);
	  offset += 128;
#ifdef DEVELOPMENT
	  {
	    const guint8 *zeros;
	    int j;
	    zeros = tvb_get_ptr(tvb, offset, 1920);
	    for (j = 0; j < 1920; j++) {
	      if (zeros[j] != 0) {
		proto_tree_add_boolean_format(sub_tree,
					      hf_uru_incomplete_dissection,
					      tvb, offset+j, 1,
					      1, "UNKNOWN DATA");
	      }
	    }
	  }
#endif
	  offset += 1920; /* 2464-(16+128+128+128+128+16) */
	  val = tvb_get_letohl(tvb, offset);
	  if (val != 0) {
	    proto_item_append_text(ti, " (%u)", val);
	  }
	  proto_tree_add_item(sub_tree, hf_urulive_age_inum, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  tf = proto_tree_add_item(sub_tree, hf_urulive_pubage_unk1, tvb,
				   offset, 4, TRUE);
	  if (global_uru_hide_stuff && val == 0xffffffff) {
	    PROTO_ITEM_SET_HIDDEN(tf);
	  }
	  offset += 4;
	  proto_tree_add_item(sub_tree, hf_urulive_pubage_owners, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(sub_tree, hf_urulive_pubage_pop, tvb, offset,
			      4, TRUE);
	  offset += 4;
	}
      }
      else if (msgtype16 == kAuth2Cli_ScoreGetScoresReply) {
	guint32 val;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	val = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_unk1, tvb, offset,
			    4, TRUE);
	offset += 4;
	val = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(uru_tree, hf_urulive_score_mlen, tvb, offset,
			    4, TRUE);
	offset += 4;
	if (val > 0) {
	  proto_tree_add_item(uru_tree, hf_urulive_score_id, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_score_holder, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  val = tvb_get_letohl(tvb, offset);
	  tf = proto_tree_add_item(uru_tree, hf_urulive_score_ts, tvb, offset,
				   4, TRUE);
	  append_ts_formatted(tf, val, 0, FALSE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_score_type, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  proto_tree_add_item(uru_tree, hf_urulive_score_value, tvb, offset,
			      4, TRUE);
	  offset += 4;
	  slen = tvb_get_letohl(tvb, offset);
	  offset += 4;
	  str = get_widestring(tvb, offset, &slen);
	  proto_tree_add_STR(uru_tree, hf_urulive_score_name, tvb, offset,
			     slen, str);
	  MAYBE_FREE(str);
	  offset += slen;
	}
      }
      else if (msgtype16 == kAuth2Cli_ScoreAddPointsReply
	       || msgtype16 == kAuth2Cli_ScoreTransferPointsReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_ScoreCreateReply) {
	guint32 val;

	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_score_id, tvb, offset,
			    4, TRUE);
	offset += 4;
	val = tvb_get_letohl(tvb, offset);
	tf = proto_tree_add_item(uru_tree, hf_urulive_score_ts, tvb, offset,
				 4, TRUE);
	append_ts_formatted(tf, val, 0, FALSE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_AcctChangePasswordReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else if (msgtype16 == kAuth2Cli_KickedOff) {
	proto_tree_add_item(uru_tree, hf_urulive_result, tvb, offset, 4, TRUE);
	offset += 4;
      }
      else if (live_conv->isgame > 0
	       && msgtype16 == kGame2Cli_JoinAgeReply) {
	proto_tree_add_item(uru_tree, hf_urulive_reqid, tvb, offset,
			    4, TRUE);
	offset += 4;
	proto_tree_add_item(uru_tree, hf_urulive_login_unk0, tvb, offset,
			    4, TRUE);
	offset += 4;
      }
      else {
	tf = proto_tree_add_boolean(uru_tree, hf_uru_incomplete_dissection,
				    tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(tf);
      }
    }
  }

  if (tree) {
  show_unknown:
    if (tvb_length_remaining(tvb, offset) > 0
	&& packettype != kAuth2Cli_FileDownloadChunk) {
	    tvbuff_t *ftvb;
	    gint bufsize, i;
	    guint8 *newbuf;

	    bufsize = tvb_length_remaining(tvb, offset);
	    newbuf = tvb_memdup(tvb, offset, bufsize);
	    for (i = 0; i < bufsize; i++) {
	      newbuf[i] = ~newbuf[i];
	    }
	    ftvb = tvb_new_real_data(newbuf, bufsize, bufsize);
	    tvb_set_child_real_data_tvbuff(tvb, ftvb);
	    tvb_set_free_cb(ftvb, g_free);
	    add_new_data_source(pinfo, ftvb, "Bit-flipped Message Body");
	    tf = proto_tree_add_boolean_format(uru_tree,
					       hf_uru_incomplete_dissection,
					       tvb, offset, bufsize,
					       1, "UNKNOWN DATA");
    }
  }
}

static guint
get_urulive_message_len(gboolean *final,
			packet_info *pinfo, tvbuff_t *etvb, int offset,
			guint32 seq) {
  guint8 msgtype, msgflags;
  guint16 msgtype16;
  guint32 len, len2, len3, len4;
  guint length_remaining;
  tvbuff_t *tvb;
  gboolean temp;

  if (!final) {
    final = &temp;
  }

  *final = TRUE;
  length_remaining = tvb_length_remaining(etvb, offset);
  if (length_remaining < 2) {
    *final = FALSE;
    return 2;
  }
  msgtype = tvb_get_guint8(etvb, offset);
  msgflags = tvb_get_guint8(etvb, offset+1);

  /* current best way to detect a data server when we don't already know */
  if (live_conv->isdata != CERTAIN_NO && live_conv->isdata != CERTAIN_YES
      && msgtype == 0x0c && msgflags == 0x00 && length_remaining == 12) {
    /* chances are very, very, good! */
    live_conv->isdata = GUESS_YES;
  }

  if (live_conv->isdata > 0 && !(msgtype == 0x10 && msgflags == 0x1f)) {
    if (length_remaining < 4) {
      *final = FALSE;
      return 4;
    }
    len = tvb_get_letohl(etvb, offset);
    if (len > 32796) {
      /* This is a hack to try to catch the corner cases where the plugin
	 isn't looking at the begining of a message and grabs some giant
	 number as the length; this way packets will be badly handled until
	 the next message that starts at a packet boundary, but that's better
	 than all the messages for the rest of the trace being eaten by the
	 desegmentation. It appears that a payload of 32k is the maximum per
	 chunk, which means a 32796-byte maximum message length. */
      return length_remaining;
    }
    return len;
  }

  /* determine whether the connection is encrypted */
  if (live_conv->negotiation_done && !live_conv->state_known) {
    /* this is the first packet in either direction after the negotiation
       but it better be from the client */
    if (isclient) {
      live_conv->state_known = TRUE;
      /* it is rather unlikely the first two bytes of an encrypted stream
	 match the original */
      if (msgflags == 0
	  && ((live_conv->isv1 > 0
	       && (msgtype == kCli2Auth_ClientRegisterRequest_v1
		   || msgtype == kCli2Game_JoinAgeRequest_v1))
	      || (live_conv->isv1 <= 0
		  && (msgtype == kCli2Auth_ClientRegisterRequest
		      || msgtype == kCli2GateKeeper_FileSrvIpAddressRequest
		      || msgtype == kCli2GateKeeper_AuthSrvIpAddressRequest
		      || msgtype == kCli2Game_JoinAgeRequest)))) {
	live_conv->is_encrypted = FALSE;
      }
      else {
	live_conv->is_encrypted = TRUE;
	urulive_setup_crypto(seq, pinfo->srcport);
      }
    }
  }

  /* in the face of encrypted streams, we may be looking at gibberish here */
  if (!live_conv->negotiation_done && !live_conv->state_known
      && live_conv->isdata < 0) {
    if (! ((msgflags == 0x1f
            && (msgtype == NegotiateAuth || msgtype == NegotiateFile
                || msgtype == NegotiateGame || msgtype == NegotiateGate))
           || (msgflags == 0x42 && msgtype == NegotiateNonce)
           || (msgflags == 0x09 && msgtype == NegotiateNonceResp)) ) {
      /* this message does not match a negotiation message and we don't
	 already think it's a data server */
      live_conv->negotiation_done = TRUE;
      live_conv->state_known = TRUE;
      live_conv->is_encrypted = TRUE;
    }
  }

  if (live_conv->is_encrypted
      && ((isclient && live_conv->c2s_crypt_zero <= seq)
	  || (!isclient && live_conv->s2c_crypt_zero <= seq))) {
    guint8 *newbuf;
    guint32 port;
    struct rc4_key *key;

    port = (isclient ? pinfo->srcport : pinfo->destport);
    key = find_rc4_key(port);
    if (!global_urulive_decrypt || !key
	|| (isclient && live_conv->c2s_next_state.seq == 0)
	|| (!isclient && live_conv->s2c_next_state.seq == 0)) {
      /* we can't decrypt this */
      return length_remaining;
    }
    /* let's limit our work (no need to copy/decrypt 32k messages) */
    len = MIN(length_remaining, 500);
    newbuf = tvb_memdup(etvb, offset, len);
    urulive_decrypt(seq, FALSE, newbuf, len);
    tvb = tvb_new_real_data(newbuf, len, len);
    tvb_set_child_real_data_tvbuff(etvb, tvb);
    tvb_set_free_cb(tvb, g_free);
    offset = 0;
    /* recompute these with decrypted data */
    msgtype = tvb_get_guint8(tvb, offset);
    msgflags = tvb_get_guint8(tvb, offset+1);
  }
  else {
    tvb = etvb;
  }

  /* msgflags is sometimes a length */
  if (msgflags == 0x1f) {
    if (length_remaining < 35) {
      *final = FALSE;
      return 35;
    }
    len = tvb_get_letohl(tvb, offset+31);
    return 0x1f+len;
  }
  else if (msgflags == 0x42 || msgflags == 0x09) {
    /* 0x42 = nonce, 0x09 = reply to nonce */
    return msgflags;
  }

  /* When the messages got renumbered, this process got even hairier. While
     before there were a couple of numbers in common between auth and game
     and most especially the key messages were different, now,
     PropagateBuffer has the same number as something else and I do not want
     to have to take apart every one of those messages to try to figure out
     which kind of server it is. So now we keep state about what kind of
     server it is and try to detect it overall instead of on a
     per-message basis. */
  msgtype16 = msgtype;
  if (live_conv->isv1 > 0) {
    msgtype16 = get_v2_value(msgtype);

    /* if msgtype == 0xffff we can't tell without looking inside the message */
    if (msgtype16 == 0xffff) {
      /* variable-length, no length field :( */
      if (length_remaining < 6) {
	*final = FALSE;
	return 6;
      }
      /* XXX very yucky heuristic */
      if (tvb_get_letohl(tvb, offset+2) > 10) {
	live_conv->isgame = GUESS_NO;
      }
      else {
	live_conv->isgame = GUESS_YES;
      }
      /* now try again */
      msgtype16 = get_v2_value(msgtype);
    }
  }
  else {
    if (global_urulive_detect_version && live_conv->ispre9 == GUESS_YES
	&& ((isclient && msgtype16 == kCli2Auth_SendFriendInviteRequest)
	    || (!isclient && msgtype16 == kAuth2Cli_SendFriendInviteReply))) {
      live_conv->ispre9 = GUESS_NO;
    }
    msgtype16 = get_9_value(msgtype, live_conv->ispre9);
  }
  if (live_conv->isgame == NO_GUESS && msgtype16 > kCli2Game_GameMgrMsg) {
    live_conv->isgame = GUESS_NO;
  }

  if (isclient) {
    switch (msgtype16) {

    case kCli2Auth_PingRequest: /* 0x00
    case kCli2Game_PingRequest:
    case kCli2GateKeeper_PingRequest: */
      return 14;

    case kCli2Auth_ClientRegisterRequest: /* 0x01
    case kCli2Game_JoinAgeRequest:
    case kCli2GateKeeper_FileSrvIpAddressRequest: */
      if (live_conv->isgate > 0) {
	return 7;
      }
      else if (live_conv->isgame < 0) {
	return 6;
      }
      else {
	return 30;
      }

    case kCli2Auth_ClientSetCCRLevel: /* 0x02
    case kCli2Game_PropagateBuffer:
    case kCli2GateKeeper_AuthSrvIpAddressRequest: */
      if (live_conv->isgate > 0) {
	return 7;
      }
      else if (live_conv->isgame < 0) {
	/* unknown */
	break;
      }
      else {
	if (length_remaining < 10) {
	  *final = FALSE;
	  return 10;
	}
	len = tvb_get_letohl(tvb, offset+6);
	return 10+len;
      }

    case kCli2Auth_AcctLoginRequest: /* 0x03
    case kCli2Game_GameMgrMsg: */
      if (live_conv->isgame < 0) {
	if (length_remaining < 12) {
	  *final = FALSE;
	  return 12;
	}
	len = tvb_get_letohs(tvb, offset+10) & 0x0FFF;
	if (length_remaining < 12+(2*len)+24) {
	  *final = FALSE;
	  return 12+(2*len)+24;
	}
	len2 = tvb_get_letohs(tvb, offset+12+(2*len)+20) & 0x0FFF;
	if (length_remaining < 12+(2*len)+22+(2*len2)+2) {
	  *final = FALSE;
	  return 12+(2*len)+22+(2*len2)+2;
	}
	len3 = tvb_get_letohs(tvb, offset+12+(2*len)+22+(2*len2)) & 0x0FFF;
	return 12+(2*len)+22+(2*len2)+2+(2*len3);
      }
      else {
	if (length_remaining < 6) {
	  *final = FALSE;
	  return 6;
	}
	len = tvb_get_letohl(tvb, offset+2);
	return 6+len;
      }

    case kCli2Auth_AcctSetPlayerRequest: /* 0x06 */
    case kCli2Auth_PlayerDeleteRequest: /* 0x0D */
    case kCli2Auth_VaultNodeFetch: /* 0x1A */
    case kCli2Auth_VaultFetchNodeRefs: /* 0x1F */
    case kCli2Auth_VaultSendNode: /* 0x23 */
      return 10;

    case kCli2Auth_AcctChangePasswordRequest: /* 0x08 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      return 8+(2*len)+20;
    case kCli2Auth_PlayerCreateRequest: /* 0x11 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      if (length_remaining < 8+(2*len)+2) {
	*final = FALSE;
	return 8+(2*len)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+8+(2*len)) & 0x0FFF;
      if (length_remaining < 8+(2*len)+2+(2*len2)+2) {
	*final = FALSE;
	return 8+(2*len)+2+(2*len2)+2;
      }
      len3 = tvb_get_letohs(tvb, offset+8+(2*len)+2+(2*len2)) & 0x0FFF;
      return 8+(2*len)+2+(2*len2)+2+(2*len3);
    case kCli2Auth_UpgradeVisitorRequest: /* 0x14 */
      return 10;
    case kCli2Auth_SendFriendInviteRequest: /* 0x18 */
      if (length_remaining < 24) {
	*final = FALSE;
	return 24;
      }
      len = tvb_get_letohs(tvb, offset+22);
      if (length_remaining < 24+(2*len)+2) {
	*final = FALSE;
	return 24+(2*len)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+24+(2*len));
      return 24+(2*len)+2+(2*len2);
    case kCli2Auth_VaultNodeCreate: /* 0x19 */
      if (length_remaining < 10) {
	*final = FALSE;
	return 10;
      }
      len = tvb_get_letohl(tvb, offset+6);
      return 10+len;
    case kCli2Auth_VaultNodeSave: /* 0x1B */
      if (live_conv->ispre4 > 0) {
	if (length_remaining < 26) {
	  *final = FALSE;
	  return 26;
	}
	len = tvb_get_letohl(tvb, offset+22);
	return 26 + len;
      }
      else {
	if (length_remaining < 30) {
	  *final = FALSE;
	  return 30;
	}
	len = tvb_get_letohl(tvb, offset+26);
	return 30 + len;
      }
    case kCli2Auth_VaultNodeAdd: /* 0x1D */
      if (live_conv->ispre4 > 0) {
	return 14;
      }
      else {
	return 18;
      }
    case kCli2Auth_VaultNodeRemove: /* 0x1E */
      if (live_conv->ispre4 > 0) {
	return 10;
      }
      else {
	return 14;
      }
    case kCli2Auth_VaultInitAgeRequest: /* 0x20 */
      if (length_remaining < 40) {
	*final = FALSE;
	return 40;
      }
      len = tvb_get_letohs(tvb, offset+38) & 0x0FFF;
      if (length_remaining < 40+(2*len)+2) {
	*final = FALSE;
	return 40+(2*len)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+40+(2*len)) & 0x0FFF;
      if (length_remaining < 40+(2*len)+2+(2*len2)+2) {
	*final = FALSE;
	return 40+(2*len)+2+(2*len2)+2;
      }
      len3 = tvb_get_letohs(tvb, offset+40+(2*len)+2+(2*len2)) & 0x0FFF;
      if (length_remaining < 40+(2*len)+2+(2*len2)+2+(2*len3)+2) {
	*final = FALSE;
	return 40+(2*len)+2+(2*len2)+2+(2*len3)+2;
      }
      len4 = tvb_get_letohs(tvb,
			    offset+40+(2*len)+2+(2*len2)+2+(2*len3)) & 0x0FFF;
      return 40+(2*len)+2+(2*len2)+2+(2*len3)+2+(2*len4)+8;
    case kCli2Auth_VaultNodeFind: /* 0x21 */
      if (length_remaining < 10) {
	*final = FALSE;
	return 10;
      }
      len = tvb_get_letohl(tvb, offset+6);
      return 10+len;
    case kCli2Auth_AgeRequest: /* 0x24 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      return 8+(2*len)+16;
    case kCli2Auth_FileListRequest: /* 0x25 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      if (length_remaining < 8+(2*len)+2) {
	*final = FALSE;
	return 8+(2*len)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+8+(2*len)) & 0x0FFF;
      return 8+(2*len)+2+(2*len2);
    case kCli2Auth_FileDownloadRequest: /* 0x26 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      return 8+(len*2);
    case kCli2Auth_FileDownloadChunkAck: /* 0x27 */
      if (global_urulive_detect_version && live_conv->ispre4 != CERTAIN_YES) {
	live_conv->ispre4 = CERTAIN_NO;
      }
      return 6;
    case kCli2Auth_GetPublicAgeList: /* 0x29 */
      if (length_remaining < 8) {
	*final = FALSE;
	return 8;
      }
      len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
      return 8+(2*len);
    case kCli2Auth_SetAgePublic: /* 0x2A */
      return 7;
    case kCli2Auth_ScoreGetScores: /* 0x30 */
      if (length_remaining < 12) {
	*final = FALSE;
	return 12;
      }
      len = tvb_get_letohs(tvb, offset+10) & 0x0FFF;
      return 12+(2*len);
    case kCli2Auth_ScoreAddPoints: /* 0x31 */
      return 14;
    case kCli2Auth_ScoreCreate: /* 0x2E */
      if (length_remaining < 12) {
	*final = FALSE;
	return 12;
      }
      len = tvb_get_letohs(tvb, offset+10) & 0x0FFF;
      return 12+(2*len)+8;
    case kCli2Auth_ScoreTransferPoints: /* 0x32 */
      return 18;
    case kCli2Auth_LogPythonTraceback: /* 0x2B */
    case kCli2Auth_LogStackDump: /* 0x2C */
    case kCli2Auth_LogClientDebuggerConnect: /* 0x2D */
      if (length_remaining < 4) {
	*final = FALSE;
	return 4;
      }
      len = tvb_get_letohs(tvb, offset+2) & 0x0FFF;
      return 4+(2*len);
    }
  }
  else { /* !isclient */
    switch (msgtype16) {

    case kAuth2Cli_PingReply: /* 0x00
    case kGame2Cli_PingReply:
    case kGateKeeper2Cli_PingReply: */
      return 14;

    case kAuth2Cli_ServerAddr: /* 0x01
    case kGame2Cli_JoinAgeReply:
    case kGateKeeper2Cli_FileSrvIpAddressReply: */
      if (live_conv->isgate > 0) {
	if (length_remaining < 8) {
	  *final = FALSE;
	  return 8;
	}
	len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
	return 8+(2*len);
      }
      else if (live_conv->isgame < 0) {
	return 22;
      }
      else {
	return 10;
      }

    case kAuth2Cli_NotifyNewBuild: /* 0x02
    case kGame2Cli_PropagateBuffer:
    case kGateKeeper2Cli_AuthSrvIpAddressReply: */
      if (live_conv->isgate > 0) {
	if (length_remaining < 8) {
	  *final = FALSE;
	  return 8;
	}
	len = tvb_get_letohs(tvb, offset+6) & 0x0FFF;
	return 8+(2*len);
      }
      else if (live_conv->isgame < 0) {
	/* XXX unknown */
	break;
      }
      else {
	if (length_remaining < 10) {
	  *final = FALSE;
	  return 10;
	}
	len = tvb_get_letohl(tvb, offset+6);
	return 10+len;
      }

    case kAuth2Cli_ClientRegisterReply: /* 0x03
    case kGame2Cli_GameMgrMsg: */
      if (live_conv->isgame < 0) {
	return 6;
      }
      else {
	if (length_remaining < 6) {
	  *final = FALSE;
	  return 6;
	}
	len = tvb_get_letohl(tvb, offset+2);
	return 6+len;
      }

    case kAuth2Cli_AcctLoginReply: /* 0x04 */
      return 50;

    case kAuth2Cli_AcctSetPlayerReply: /* 0x07 */
    case kAuth2Cli_AcctChangePasswordReply: /* 0x09 */
    case kAuth2Cli_PlayerDeleteReply: /* 0x11 */
    case kAuth2Cli_SendFriendInviteReply: /* 0x15 */
    case kAuth2Cli_VaultNodeRemoved: /* 0x1C */ /* 10 in Live 4 */
    case kAuth2Cli_VaultSaveNodeReply: /* 0x20 */
    case kAuth2Cli_VaultAddNodeReply: /* 0x21 */
    case kAuth2Cli_VaultRemoveNodeReply: /* 0x22 */
      return 10;
    case kAuth2Cli_VaultNodeCreated: /* 0x17 */
    case kAuth2Cli_VaultNodeAdded: /* 0x1B */
      return 14;

    case kAuth2Cli_AcctPlayerInfo: /* 0x06 */
      if (length_remaining < 12) {
	*final = FALSE;
	return 12;
      }
      len = tvb_get_letohs(tvb, offset+10) & 0x0FFF;
      if (length_remaining < 12+(len*2)+2) {
	*final = FALSE;
	return 12+(len*2)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+12+(len*2)) & 0x0FFF;
      return 12+(len*2)+2+(len2*2)+4;
    case kAuth2Cli_PlayerCreateReply: /* 0x10 */
      if (length_remaining < 20) {
	*final = FALSE;
	return 20;
      }
      len = tvb_get_letohs(tvb, offset+18) & 0x0FFF;
      if (length_remaining < 20+(len*2)+2) {
	*final = FALSE;
	return 20+(len*2)+2;
      }
      len2 = tvb_get_letohs(tvb, offset+20+(len*2)) & 0x0FFF;
      return 20+(len*2)+2+(len2*2);
    case kAuth2Cli_VaultNodeFetched: /* 0x18 */
      if (length_remaining < 14) {
	*final = FALSE;
	return 14;
      }
      len = tvb_get_letohl(tvb, offset+10);
      return 14+len;
    case kAuth2Cli_VaultNodeChanged: /* 0x19 */
      return 22;
    case kAuth2Cli_VaultNodeDeleted: /* 0x1A */
      /* XXX unknown */
      return length_remaining;
    case kAuth2Cli_VaultNodeRefsFetched: /* 0x1D */
      if (length_remaining < 14) {
	*final = FALSE;
	return 14;
      }
      len = tvb_get_letohl(tvb, offset+10);
      return 14+(13*len);
    case kAuth2Cli_VaultInitAgeReply: /* 0x1E */
      return 18;
    case kAuth2Cli_VaultNodeFindReply: /* 0x1F */
      if (length_remaining < 14) {
	*final = FALSE;
	return 14;
      }
      len = tvb_get_letohl(tvb, offset+10);
      return 14+(4*len);
    case kAuth2Cli_AgeReply: /* 0x23 */
      return 38;
    case kAuth2Cli_FileListReply: /* 0x24 */
      if (length_remaining < 14) {
	*final = FALSE;
	return 14;
      }
      len = tvb_get_letohl(tvb, offset+10);
      return 14+(2*len); /* um, okay, whatever... */
    case kAuth2Cli_FileDownloadChunk: /* 0x25 */
      if (live_conv->ispre4 > 0) {
	if (length_remaining < 18) {
	  *final = FALSE;
	  return 18;
	}
	len = tvb_get_letohl(tvb, offset+14);
	return 18+len;
      }
      else {
	if (length_remaining < 22) {
	  *final = FALSE;
	  return 22;
	}
	len = tvb_get_letohl(tvb, offset+18);
	return 22+len;
      }
    case kAuth2Cli_KickedOff: /* 0x27 */
      return 6;
    case kAuth2Cli_PublicAgeList: /* 0x28 */
      if (length_remaining < 14) {
	*final = FALSE;
	return 14;
      }
      len = tvb_get_letohl(tvb, offset+10);
      return 14+(2464*len);
    case kAuth2Cli_ScoreGetScoresReply: /* 0x2B */
      if (length_remaining < 18) {
	*final = FALSE;
	return 18;
      }
      /* XXX this is a maybe until I see something other than PelletDrop */
      len = tvb_get_letohl(tvb, offset+14);
      return 18+len;
    case kAuth2Cli_ScoreAddPointsReply: /* 0x2C */
    case kAuth2Cli_ScoreTransferPointsReply: /* 0x2D */
      return 10;
    case kAuth2Cli_ScoreCreateReply: /* 0x29 */
      return 18;
    }
  }
  /* remaining types */
#if 0
  switch (msgtype16) {
    case kCli2Auth_ClientSetCCRLevel: /* 0x02 */
    case kAuth2Cli_NotifyNewBuild: /* 0x02 */
    case kCli2Auth_AcctCreateRequest: /* 0x07 */
    case kAuth2Cli_AcctCreateReply: /* 0x08 */
    case kCli2Auth_AcctSetRolesRequest: /* 0x09 */
    case kCli2Auth_AcctSetBillingTypeRequest: /* 0x0A */
    case kAuth2Cli_AcctSetRolesReply: /* 0x0A */
    case kCli2Auth_AcctActivateRequest: /* 0x0B */
    case kAuth2Cli_AcctSetBillingTypeReply: /* 0x0B */
    case kCli2Auth_AcctCreateFromKeyRequest: /* 0x0C */
    case kAuth2Cli_AcctActivateReply: /* 0x0C */
    case kAuth2Cli_AcctCreateFromKeyReply: /* 0x0D */
    case kAuth2Cli_UpgradeVisitorReply: /* 0x12 */
    case kAuth2Cli_SetPlayerBanStatusReply: /* 0x13*/
    case kAuth2Cli_ChangePlayerNameReply: /* 0x14 */
    case kCli2Auth_SetPlayerBanStatusRequest: /* 0x15 */
    case kCli2Auth_KickPlayer: /* 0x16 */
    case kCli2Auth_ChangePlayerNameRequest: /* 0x17 */
    case kCli2Auth_VaultSetSeen: /* 0x22 */
    case kAuth2Cli_PropagateBuffer: /* 0x26 */
    case kCli2Auth_PropagateBuffer: /* 0x28 */
    case kAuth2Cli_ScoreDeleteReply: /* 0x2A */
    case kAuth2Cli_ScoreSetPointsReply: /* 0x2E */
    case kCli2Auth_ScoreDelete: /* 0x2F */
    case kAuth2Cli_ScoreGetRanksReply: /* 0x2F */
    case kCli2Auth_ScoreSetPoints: /* 0x33 */
    case kCli2Auth_ScoreGetRanks: /* 0x34 */
  }
#endif
  /* unknown */
  return length_remaining;
}

static void
dissect_urulive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  conversation_t *conv;
  enum fourstate guess;

  conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			   pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  if (!conv) {
    conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
  }
  live_conv
    = (struct urulive_conv *)conversation_get_proto_data(conv, proto_urulive);
  if (!live_conv) {
    live_conv = (struct urulive_conv*)se_alloc(sizeof(struct urulive_conv));
    /* conversation properties */
    live_conv->isdata = GUESS_NO;
    live_conv->isgame = NO_GUESS;
    if (global_urulive_detect_version) {
      guess = GUESS_YES;
    }
    else {
      guess = CERTAIN_YES;
    }
    if (global_urulive_is_pre4) {
      live_conv->ispre4 = guess;
      /* pre4 overrides v1 if they conflict (pre4 = true, v1 = false) */
      live_conv->isv1 = guess;
      live_conv->ispre9 = guess;
    }
    else if (global_urulive_is_v1) {
      live_conv->ispre4 = -guess;
      live_conv->isv1 = guess;
      live_conv->ispre9 = guess;
    }
    else if (global_urulive_is_pre9) {
      live_conv->ispre4 = -guess;
      live_conv->isv1 = -guess;
      live_conv->ispre9 = guess;
    }
    else {
      live_conv->ispre4 = -guess;
      live_conv->isv1 = -guess;
      live_conv->ispre9 = -guess;
    }
    live_conv->c2s_last_frame = live_conv->s2c_last_frame = 0;
    /* crypto */
    live_conv->negotiation_done = FALSE;
    if (global_urulive_detect_version) {
      live_conv->state_known = FALSE;
      live_conv->is_encrypted = FALSE;
    }
    else {
      live_conv->state_known = TRUE;
      live_conv->is_encrypted = global_urulive_is_encrypted;
    }
#ifdef HAVE_LIBGCRYPT
    live_conv->key_half[0] = 0;
#endif
    live_conv->c2s_crypt_zero = 0;
    live_conv->s2c_crypt_zero = 0;
    live_conv->c2s_rc4_states
      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
				      "urulive c2s RC4 state");
    live_conv->s2c_rc4_states
      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
				      "urulive s2c RC4 state");
    live_conv->c2s_next_state.seq = 0;
    live_conv->s2c_next_state.seq = 0;
    /* for desegmentation */
    live_conv->c2s_multisegment_pdus
      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "urulive c2s");
    live_conv->s2c_multisegment_pdus
      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "urulive s2c");

    conversation_add_proto_data(conv, proto_urulive, (void *)live_conv);
  }

  if (pinfo->destport == global_urulive_port) {
    isclient = TRUE;
  }
  else {
    isclient = FALSE;
  }

  if (global_urulive_desegment && pinfo->can_desegment) {
    emem_tree_t *which;
    which = isclient ? live_conv->c2s_multisegment_pdus
		     : live_conv->s2c_multisegment_pdus;
    desegment_urutcp(tvb, pinfo, tree, which);
  }
  else {
    dissect_urulive_message(tvb, pinfo, tree,
			    ((struct tcpinfo *)pinfo->private_data)->seq);
  }
}

/********** end of dissectors **********/

#ifdef EPHEMERAL_BUFS
/* do NOT free returned pointers */
#else
/* if a non-NULL value is returned, it must be freed */
#endif
static char *
get_uru_widestring(tvbuff_t *tvb, gint offset, guint *len)
{
  int i;
  char *string;
  guint16 strinfo, length;
  guint8 flipped, *newbuf;
  tvbuff_t *ntvb;

  strinfo = tvb_get_letohs(tvb, offset);
  length = strinfo & 0x0FFF;
  flipped = (strinfo & 0xF000) >> 8;
  *len = (2*length)+2;
  if (length == 0) {
    return NULL;
  }
  if (flipped) {
    newbuf = tvb_memdup(tvb, offset+2, 2*length);
    for (i = 0; i < 2*length; i++) {
      newbuf[i] = ~newbuf[i];
    }
    ntvb = tvb_new_real_data(newbuf, 2*length, 2*length);
    offset = 0;
  }
  else {
    ntvb = tvb;
    offset += 2;
  }
#ifdef EPHEMERAL_BUFS
  string = tvb_get_ephemeral_faked_unicode(ntvb, offset, length, TRUE);
#else
  string = (char*)tvb_fake_unicode(ntvb, offset, length, TRUE);
#endif
  if (flipped) {
    /* there are no child tvbuffs, so this is safe */
    tvb_free(ntvb);
    g_free(newbuf);
  }
  return string;
}

/*
 * *len must contain the length remaining in the message when this is
 * called and on return it will contain the length of the string (counting
 * the NUL)
 */
#ifdef EPHEMERAL_BUFS
/* do NOT free returned pointers */
#else
/* if a non-NULL value is returned, it must be freed */
#endif
static char *
get_widestring(tvbuff_t *tvb, gint offset, guint *len)
{
  guint i;
  guint thelen;
  char *string;

  for (i = 0; i+1 < *len; i += 2) {
    if (tvb_get_guint8(tvb, offset+i) == 0
	&& tvb_get_guint8(tvb, offset+i+1) == 0) {
      *len = i+2;
      break;
    }
  }
  thelen = (*len)/2;

#ifdef EPHEMERAL_BUFS
  string = tvb_get_ephemeral_faked_unicode(tvb, offset, thelen, TRUE);
#else
  string = tvb_fake_unicode(tvb, offset, thelen, TRUE);
#endif
  return string;
}

static proto_item * urulive_add_stringlen(proto_tree *tree, tvbuff_t *tvb,
					  gint offset, int hf)
{
  guint16 upper, lower, thenul;
  guint32 len;
  proto_item *ti;

  upper = tvb_get_letohs(tvb, offset);
  lower = tvb_get_letohs(tvb, offset+2);
  thenul = tvb_get_letohs(tvb, offset+4);
  len = (upper << 16) | lower;
  ti = proto_tree_add_uint_format_value(tree, hf, tvb, offset, 6, len,
					"%u%s", len,
					thenul ? " (NOT null-terminated!)"
					       : "");
  return ti;
}

static void urulive_setup_crypto(guint32 seq, guint32 port) {
  struct rc4_state_cache *cache;
  struct rc4_key *key;

  if (isclient) {
    live_conv->c2s_crypt_zero = seq;
  }
  else {
    live_conv->s2c_crypt_zero = seq;
  }

  key = find_rc4_key(port);

  if (key != NULL) {
    live_conv->c2s_next_state.seq = live_conv->c2s_crypt_zero;
    live_conv->s2c_next_state.seq = live_conv->s2c_crypt_zero;

    cache = se_alloc(sizeof(struct rc4_state_cache));

    if (!isclient) {
      crypt_rc4_init(&live_conv->s2c_next_state.s, key->key, 7);
      memcpy(&live_conv->c2s_next_state.s, &live_conv->s2c_next_state.s,
	   sizeof(rc4_state_struct));
    }

    if (isclient) {
      memcpy(cache, &live_conv->c2s_next_state,
	     sizeof(struct rc4_state_cache));
      se_tree_insert32(live_conv->c2s_rc4_states, seq, cache);
    }
    else {
      memcpy(cache, &live_conv->s2c_next_state,
	     sizeof(struct rc4_state_cache));
      se_tree_insert32(live_conv->s2c_rc4_states, seq, cache);
    }
  }
  else {
    /* no key known */
  }
}

/* this function does RC4 data_len times without actually encrypting
   anything */
/* copied from epan/crypt/crypt-rc4.c */
static void crypt_rc4_evolve(rc4_state_struct *rc4_state, int data_len) {
  unsigned char *s_box;
  unsigned char index_i;
  unsigned char index_j;
  int ind;

  /* retrieve current state from the state struct (so we can resume where
     we left off) */
  index_i = rc4_state->index_i;
  index_j = rc4_state->index_j;
  s_box = rc4_state->s_box;

  for( ind = 0; ind < data_len; ind++)
  {
    unsigned char tc;
    unsigned char t;

    index_i++;
    index_j += s_box[index_i];

    tc = s_box[index_i];
    s_box[index_i] = s_box[index_j];
    s_box[index_j] = tc;

    t = s_box[index_i] + s_box[index_j];
    /* data[ind] = data[ind] ^ s_box[t]; */
  }

  /* Store the updated state */
  rc4_state->index_i = index_i;
  rc4_state->index_j = index_j;
}

static void urulive_decrypt(guint32 seq, gboolean advance,
			    guint8 *buf, int len) {
  emem_tree_t *tree;
  struct rc4_state_cache *cache, *prev, local;

  if (isclient) {
    tree = live_conv->c2s_rc4_states;
    cache = &(live_conv->c2s_next_state);
  }
  else {
    tree = live_conv->s2c_rc4_states;
    cache = &(live_conv->s2c_next_state);
  }

  prev = (struct rc4_state_cache *)se_tree_lookup32_le(tree, seq);
  if (cache->seq <= seq) {
    if (!advance) {
      memcpy(&local, cache, sizeof(struct rc4_state_cache));
      cache = &local;
    }
    if (cache->seq < seq) {
      crypt_rc4_evolve(&cache->s, seq - cache->seq);
      cache->seq = seq;
    }
    crypt_rc4(&cache->s, buf, len);
    cache->seq += len;
    if (/* this should not happen */prev == NULL
	|| (prev->seq + RC4_CACHE_FREQ < cache->seq)) {
      /* cache this one */
      prev = se_alloc(sizeof(struct rc4_state_cache));
      memcpy(prev, cache, sizeof(struct rc4_state_cache));
      se_tree_insert32(tree, cache->seq, prev);
    }
  }
  else {
    memcpy(&local, prev, sizeof(struct rc4_state_cache));
    if (prev->seq < seq) {
      crypt_rc4_evolve(&local.s, seq - prev->seq);
    }
    crypt_rc4(&local.s, buf, len);
  }
}

static struct rc4_key *find_rc4_key(guint32 port) {
  int i;

  if (global_urulive_rc4_keys) {
    for (i = 0; i < global_urulive_n_rc4_keys; i++) {
      /* return special key if it has been set up with our data (during
	 crypto setup) or just any non-NULL key so that the "can we decrypt"
	 test behaves well */
#ifdef HAVE_LIBGCRYPT
      if ((global_urulive_use_private_keys && live_conv->key_half[0])
	  && global_urulive_rc4_keys[i].server_port == 0xffffffff) {
	return global_urulive_rc4_keys+i;
      }
#endif
      /* return a configured key if it matches */
      if (global_urulive_rc4_keys[i].server_port != 0
	  && global_urulive_rc4_keys[i].server_port == port) {
	return global_urulive_rc4_keys+i;
      }
    }
  }
  return NULL;
}

static guint16 get_v2_value(guint16 msgtype) {
  switch (msgtype) {
  case kCli2Auth_PingRequest_v1: /* 0x00
  case kAuth2Cli_PingReply_v1:
  case kCli2Game_PingRequest_v1:
  case kGame2Cli_PingReply_v1: */
    return kCli2Auth_PingRequest; /* 0x00 */

  /* What a mess!! */
  case kAuth2Cli_ServerAddr_v1: /* 0x03 */
    if (live_conv->isgame == NO_GUESS) {
      live_conv->isgame = GUESS_NO;
    }
    return kAuth2Cli_ServerAddr; /* 0x01 */
  case kCli2Auth_ClientRegisterRequest_v1: /* 0x0A
  case kAuth2Cli_ClientRegisterReply_v1: */
    if (live_conv->isgame == NO_GUESS) {
      live_conv->isgame = GUESS_NO;
    }
    if (isclient) {
      return kCli2Auth_ClientRegisterRequest; /* 0x01 */
    }
    else {
      return kAuth2Cli_ClientRegisterReply; /* 0x03 */
    }
  case kCli2Auth_AcctLoginRequest_v1: /* 0x14
  case kAuth2Cli_AcctLoginReply_v1:
  case kCli2Game_JoinAgeRequest_v1:
  case kGame2Cli_JoinAgeReply_v1: */
    if (live_conv->isgame > 0) {
      return kCli2Game_JoinAgeRequest; /* 0x01
      return kGame2Cli_JoinAgeReply; */
    }
    else if (live_conv->isgame < 0) {
      if (isclient) {
	return kCli2Auth_AcctLoginRequest; /* 0x03 */
      }
      else {
	return kAuth2Cli_AcctLoginReply; /* 0x04 */
      }
    }
    else {
      /* unknown */
      return 0xffff; /* XXX ideally this would be out of the valid range */
    }

  case kAuth2Cli_NotifyNewBuild_v1: /* 0x04 */
  case kCli2Auth_ClientSetCCRLevel_v1: /* 0x0B */
    if (live_conv->isgame == NO_GUESS) {
      live_conv->isgame = GUESS_NO;
    }
    return kAuth2Cli_NotifyNewBuild; /* 0x02
    return kCli2Auth_ClientSetCCRLevel; */
  case kAuth2Cli_AcctPlayerInfo_v1: /* 0x16 */
    return kAuth2Cli_AcctPlayerInfo; /* 0x06 */
  case kCli2Auth_AcctSetPlayerRequest_v1: /* 0x17
  case kAuth2Cli_AcctSetPlayerReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctSetPlayerRequest; /* 0x06 */
    }
    else {
      return kAuth2Cli_AcctSetPlayerReply; /* 0x07 */
    }
  case kCli2Auth_AcctCreateRequest_v1: /* 0x18
  case kAuth2Cli_AcctCreateReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctCreateRequest; /* 0x07 */
    }
    else {
      return kAuth2Cli_AcctCreateReply; /* 0x08 */
    }
  case kCli2Auth_AcctChangePasswordRequest_v1: /* 0x19
  case kAuth2Cli_AcctChangePasswordReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctChangePasswordRequest; /* 0x08 */
    }
    else {
      return kAuth2Cli_AcctChangePasswordReply; /* 0x09 */
    }
  case kCli2Auth_AcctSetRolesRequest_v1: /* 0x1A
  case kAuth2Cli_AcctSetRolesReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctSetRolesRequest; /* 0x09 */
    }
    else {
      return kAuth2Cli_AcctSetRolesReply; /* 0x0A */
    }
  case kCli2Auth_AcctSetBillingTypeRequest_v1: /* 0x1B
  case kAuth2Cli_AcctSetBillingTypeReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctSetBillingTypeRequest; /* 0x0A */
    }
    else {
      return kAuth2Cli_AcctSetBillingTypeReply; /* 0x0B */
    }
  case kCli2Auth_AcctActivateRequest_v1: /* 0x1C
  case kAuth2Cli_AcctActivateReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctActivateRequest; /* 0x0B */
    }
    else {
      return kAuth2Cli_AcctActivateReply; /* 0x0C */
    }
  case kCli2Auth_AcctCreateFromKeyRequest_v1: /* 0x1D
  case kAuth2Cli_AcctCreateFromKeyReply_v1: */
    if (isclient) {
      return kCli2Auth_AcctCreateFromKeyRequest; /* 0x0C */
    }
    else {
      return kAuth2Cli_AcctCreateFromKeyReply; /* 0x0D */
    }
  case kCli2Game_PropagateBuffer_v1: /* 0x1E
  case kGame2Cli_PropagateBuffer_v1: */
    if (live_conv->isgame == NO_GUESS) {
      live_conv->isgame = GUESS_YES;
    }
    return kCli2Game_PropagateBuffer; /* 0x02
    return kGame2Cli_PropagateBuffer; */
  case kCli2Game_GameMgrMsg_v1: /* 0x1F
  case kGame2Cli_GameMgrMsg_v1: */
    if (live_conv->isgame == NO_GUESS) {
      live_conv->isgame = GUESS_YES;
    }
    return kCli2Game_GameMgrMsg; /* 0x03
    return kGame2Cli_GameMgrMsg; */
  case kCli2Auth_PlayerDeleteRequest_v1: /* 0x28 */
    return kCli2Auth_PlayerDeleteRequest; /* 0x0D */
  case kAuth2Cli_PlayerCreateReply_v1: /* 0x2A */
    return kAuth2Cli_PlayerCreateReply; /* 0x10 */
  case kAuth2Cli_PlayerDeleteReply_v1: /* 0x2B */
    return kAuth2Cli_PlayerDeleteReply; /* 0x11 */
  case kCli2Auth_PlayerCreateRequest_v1: /* 0x2C
  case kAuth2Cli_UpgradeVisitorReply_v1: */
    if (isclient) {
      return kCli2Auth_PlayerCreateRequest; /* 0x11 */
    }
    else {
      return kAuth2Cli_UpgradeVisitorReply; /* 0x12 */
    }
  case kAuth2Cli_SetPlayerBanStatusReply_v1: /* 0x2D */
    return kAuth2Cli_SetPlayerBanStatusReply; /* 0x13 */
  case kAuth2Cli_ChangePlayerNameReply_v1: /* 0x2E */
    return kAuth2Cli_ChangePlayerNameReply; /* 0x14 */
  case kCli2Auth_UpgradeVisitorRequest_v1: /* 0x2F */
    return kCli2Auth_UpgradeVisitorRequest; /* 0x14 */
  case kCli2Auth_SetPlayerBanStatusRequest_v1: /* 0x30 */
    return kCli2Auth_SetPlayerBanStatusRequest; /* 0x15 */
  case kCli2Auth_KickPlayer_v1: /* 0x31 */
    return kCli2Auth_KickPlayer; /* 0x16 */
  case kCli2Auth_ChangePlayerNameRequest_v1: /* 0x32 */
    return kCli2Auth_ChangePlayerNameRequest; /* 0x17 */
  /* this is total insanity */
  case kCli2Auth_VaultNodeCreate_v1: /* 0x50
  case kAuth2Cli_VaultNodeCreated_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeCreate; /* 0x19 */
    }
    else {
      return kAuth2Cli_VaultNodeCreated; /* 0x17 */
    }
  case kCli2Auth_VaultNodeFetch_v1: /* 0x51
  case kAuth2Cli_VaultNodeFetched_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeFetch; /* 0x20 */
    }
    else {
      return kAuth2Cli_VaultNodeFetched; /* 0x18 */
    }
  case kCli2Auth_VaultNodeSave_v1: /* 0x52
  case kAuth2Cli_VaultNodeChanged_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeSave; /* 0x1B */
    }
    else {
      return kAuth2Cli_VaultNodeChanged; /* 0x19 */
    }
  case kAuth2Cli_VaultNodeDeleted_v1: /* 0x53 */
    return kAuth2Cli_VaultNodeDeleted; /* 0x20 */
  case kCli2Auth_VaultNodeAdd_v1: /* 0x54
  case kAuth2Cli_VaultNodeAdded_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeAdd; /* 0x1D */
    }
    else {
      return kAuth2Cli_VaultNodeAdded; /* 0x1B */
    }
  case kCli2Auth_VaultNodeRemove_v1: /* 0x55
  case kAuth2Cli_VaultNodeRemoved_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeRemove; /* 0x1E */
    }
    else {
      return kAuth2Cli_VaultNodeRemoved; /* 0x1C */
    }
  case kCli2Auth_VaultFetchNodeRefs_v1: /* 0x56
  case kAuth2Cli_VaultNodeRefsFetched_v1: */
    if (isclient) {
      return kCli2Auth_VaultFetchNodeRefs; /* 0x1F */
    }
    else {
      return kAuth2Cli_VaultNodeRefsFetched; /* 0x1D */
    }
  case kCli2Auth_VaultInitAgeRequest_v1: /* 0x57
  case kAuth2Cli_VaultInitAgeReply_v1: */
    if (isclient) {
      return kCli2Auth_VaultInitAgeRequest; /* 0x20 */
    }
    else {
      return kAuth2Cli_VaultInitAgeReply; /* 0x1E */
    }
  case kCli2Auth_VaultNodeFind_v1: /* 0x58
  case kAuth2Cli_VaultNodeFindReply_v1: */
    if (isclient) {
      return kCli2Auth_VaultNodeFind; /* 0x21 */
    }
    else {
      return kAuth2Cli_VaultNodeFindReply; /* 0x1F */
    }
  case kCli2Auth_VaultSetSeen_v1: /* 0x59
  case kAuth2Cli_VaultSaveNodeReply_v1: */
    if (isclient) {
      return kCli2Auth_VaultSetSeen; /* 0x22 */
    }
    else {
      return kAuth2Cli_VaultSaveNodeReply; /* 0x20 */
    }
  case kCli2Auth_VaultSendNode_v1: /* 0x5A
  case kAuth2Cli_VaultAddNodeReply_v1: */
    if (isclient) {
      return kCli2Auth_VaultSendNode; /* 0x23 */
    }
    else {
      return kAuth2Cli_VaultAddNodeReply; /* 0x21 */
    }
  case kCli2Auth_VaultScoreAddPoints_v1: /* 0x5B
  case kAuth2Cli_VaultRemoveNodeReply_v1: */
    if (isclient) {
      return kCli2Auth_ScoreAddPoints; /* 0x31 */
    }
    else {
      return kAuth2Cli_VaultRemoveNodeReply; /* 0x22 */
    }
  case kCli2Auth_VaultScoreTransferPoints_v1: /* 0x5C */
    return kCli2Auth_ScoreTransferPoints; /* 0x32 */
  case kCli2Auth_AgeRequest_v1: /* 0x64
  case kAuth2Cli_AgeReply_v1: */
    if (isclient) {
      return kCli2Auth_AgeRequest; /* 0x24 */
    }
    else {
      return kAuth2Cli_AgeReply; /* 0x23 */
    }
  case kCli2Auth_FileListRequest_v1: /* 0x78
  case kAuth2Cli_FileListReply_v1: */
    if (isclient) {
      return kCli2Auth_FileListRequest; /* 0x25 */
    }
    else {
      return kAuth2Cli_FileListReply; /* 0x24 */
    }
  case kCli2Auth_FileDownloadRequest_v1: /* 0x79
  case kAuth2Cli_FileDownloadChunk_v1: */
    if (isclient) {
      return kCli2Auth_FileDownloadRequest; /* 0x26 */
    }
    else {
      return kAuth2Cli_FileDownloadChunk; /* 0x25 */
    }
  case kCli2Auth_FileDownloadChunkAck_v1: /* 0x7A */
    return kCli2Auth_FileDownloadChunkAck; /* 0x27 */
  case kCli2Auth_PropagateBuffer_v1: /* 0x8C
  case kAuth2Cli_PropagateBuffer_v1: */
    if (isclient) {
      return kCli2Auth_PropagateBuffer; /* 0x28 */
    }
    else {
      return kAuth2Cli_PropagateBuffer; /* 0x26 */
    }
  case kAuth2Cli_KickedOff_v1: /* 0xA0 */
    return kAuth2Cli_KickedOff; /* 0x27 */
  case kCli2Auth_GetPublicAgeList_v1: /* 0xB4
  case kAuth2Cli_PublicAgeList_v1: */
    if (isclient) {
      return kCli2Auth_GetPublicAgeList; /* 0x29 */
    }
    else {
      return kAuth2Cli_PublicAgeList; /* 0x28 */
    }
  case kCli2Auth_SetAgePublic_v1: /* 0xB5 */
    return kCli2Auth_SetAgePublic; /* 0x30 */
  case kCli2Auth_LogPythonTraceback_v1: /* 0xC8
  case kAuth2Cli_VaultScoreAddPointsReply_v1: */
    if (isclient) {
      return kCli2Auth_LogPythonTraceback; /* 0x2B */
    }
    else {
      return kAuth2Cli_ScoreAddPointsReply; /* 0x2C */
    }
  case kCli2Auth_LogStackDump_v1: /* 0xC9
  case kAuth2Cli_VaultScoreTransferPointsReply_v1: */
    if (isclient) {
      return kCli2Auth_LogStackDump; /* 0x2C */
    }
    else {
      return kAuth2Cli_ScoreTransferPointsReply; /* 0x2D */
    }
  case kCli2Auth_LogClientDebuggerConnect_v1: /* 0xCA */
    return kCli2Auth_LogClientDebuggerConnect; /* 0x2D */
  default:
    return msgtype;
  }
}

static inline guint16 get_9_value(guint16 msgtype, enum fourstate is_pre9) {
  if (is_pre9 < 0) {
    return msgtype;
  }
  if (isclient) {
    if (msgtype < kCli2Auth_SendFriendInviteRequest /* 0x18 */) {
      return msgtype;
    }
    else {
      return msgtype + 1;
    }
  }
  else {
    if (msgtype < kAuth2Cli_SendFriendInviteReply /* 0x15 */) {
      return msgtype;
    }
    else {
      return msgtype + 1;
    }
  }
}

static guint16 live_translate(guint16 type) {
  switch (type) {
  /* NetMsg types */
  case live_plNetMsgPagingRoom:
    return type;
  case live_plNetMsgMembersListReq:
  case live_plNetMsgGroupOwner:
  case live_plNetMsgGameMessageDirected:
  case live_plNetMsgGameMessage:
  case live_plNetMsgPlayerPage:
  case live_plNetMsgLoadClone:
  case live_plNetMsgRelevanceRegions:
  case live_plNetMsgGameStateRequest:
  case live_plNetMsgTestAndSet:
  case live_plNetMsgInitialAgeStateSent:
  case live_plNetMsgMembersList:
  case live_plNetMsgMemberUpdate:
  case live_plNetMsgSDLState:
  case live_plNetMsgSDLStateBCast:
  case live_plNetMsgVoice:
  /* GameMessage types */
  case live_pfKIMsg:
  case live_plNotifyMsg:
  case live_plInputIfaceMgrMsg:
  case live_plServerReplyMsg:
  case live_plAvatarInputStateMsg:
  case live_plLinkEffectsTriggerMsg:
  case live_plClothingMsg:
  case live_plClimbEventMsg:
  case live_plSubWorldMsg:
  case live_plEnableMsg:
  case live_plAvSeekMsg:
  case live_plAvTaskMsg:
  case live_plAvTaskBrain:
  case live_plMultistageModMsg:
  case live_plClimbMsg:
  case live_plAvBrainGenericMsg:
  case live_plAvAnimTask:
  case live_plLinkToAgeMsg:
  case live_plLoadAvatarMsg:
  case live_plLoadCloneMsg:
  case live_plParticleTransferMsg:
  case live_plParticleKillMsg:
  /* following messages probably won't be seen */
  case live_plLinkingMgrMsg:
  case live_plWarpMsg:
  case live_plAvOneShotMsg:
  case live_plShiftMassMsg:
  case live_plTorqueMsg:
  case live_plImpulseMsg:
  case live_plOffsetImpulseMsg:
  case live_plAngularImpulseMsg:
  case live_plForceMsg:
  case live_plOffsetForceMsg:
  case live_plDampMsg:
    return type - 5;
  case live_plControlEventMsg:
  /* end messages I don't expect to see */
  case live_plAnimCmdMsg:
    return type;
  case live_plPseudoLinkEffectMsg:
  case live_plAvCoopMsg:
  case live_plAvOneShotLinkTask:
  case live_plSetNetGroupIDMsg: /* new? */
    return type - 6;
  default:
    {
      if (type < 0x022F) {
	return type;
      }
      else if (type < 0x0427) {
	return type - 5;
      }
      else {
	return type - 6;
      }
    }
  }
}

/********** plugin hooks **********/

void
proto_reg_handoff_urulive(void) {
  static gboolean inited = FALSE;
  gchar **array, **pair;
  int i, j, k, l;
  guint16 port;
  guint digit;
#ifdef HAVE_LIBGCRYPT
  FILE *f;
#endif

  if (!inited) {
    urulive_handle = create_dissector_handle(dissect_urulive, proto_urulive);
    inited = TRUE;
  }
  else {
    dissector_delete("tcp.port", global_urulive_port, urulive_handle);
  }

  dissector_add("tcp.port", global_urulive_port, urulive_handle);

  /* set up for crypto */
  if (global_urulive_rc4_keys) {
    g_free(global_urulive_rc4_keys);
    global_urulive_rc4_keys = NULL;
    global_urulive_n_rc4_keys = 0;
  }

  array = ep_strsplit(global_urulive_keys, ",", 0);
  i = 0;
  while (array[i]) {
    i++;
  }
  if (global_urulive_use_private_keys) {
    i++;
  }
  if (i > 0) {
    global_urulive_rc4_keys
      = (struct rc4_key*)g_malloc(sizeof(struct rc4_key)*i);
    global_urulive_n_rc4_keys = i;
    i = 0;
    l = 0;
    if (global_urulive_use_private_keys) {
      global_urulive_rc4_keys[i].server_port = 0xffffffff;
      i++;
    }
    while (array[l]) {
      /* a port of 0 means the key is not valid */
      global_urulive_rc4_keys[i].server_port = 0;
      pair = ep_strsplit(array[l], "=", 0);
      j = 0;
      while (pair[j]) {
	j++;
      }
      if (j == 2) {
	if (sscanf(pair[0], "%hu", &port) > 0) {
	  j = strlen(pair[1])-1;
	  k = 6;
	  /* this loop starts from the end of the string and goes backward
	     so that only two characters are seen by sscanf at a time */
	  while (j > 0) {
	    if (pair[1][j] == ' ' || pair[1][j] == '\t') {
	      j--;
	      continue;
	    }
	    if (sscanf(pair[1]+j-1, "%x", &digit) > 0) {
	      global_urulive_rc4_keys[i].key[k] = digit & 0xFF;
	      k--;
	      pair[1][j-1] = '\0';
	      j -= 2;
	    }
	    else {
	      j--;
	    }
	  }
	  if (k == -1) {
	    global_urulive_rc4_keys[i].server_port = port;
	  }
	}
      }
      i++;
      l++;
    }
  }
#ifdef HAVE_LIBGCRYPT
  gcry_mpi_release(auth_modulus);
  gcry_mpi_release(auth_exponent);
  gcry_mpi_release(game_modulus);
  gcry_mpi_release(game_exponent);
  auth_modulus = auth_exponent = game_modulus = game_exponent = NULL;
  if (global_urulive_use_private_keys) {
    /* the format of the file is: 128 bytes: 64 bytes of big-endian modulus,
       then 64 bytes of big-endian key */
    if (global_urulive_auth_file) {
      if ((f = ws_fopen(global_urulive_auth_file, "rb")) != NULL) {
	guint8 data[128];
	if (fread(data, 128, 1, f) == 1) {
	  gcry_mpi_scan(&auth_modulus, GCRYMPI_FMT_USG, data, 64, NULL);
	  if (auth_modulus) {
	    gcry_mpi_scan(&auth_exponent, GCRYMPI_FMT_USG, data+64, 64, NULL);
	  }
	}
	fclose(f);
      }
    }
    if (global_urulive_game_file) {
      if ((f = ws_fopen(global_urulive_game_file, "rb")) != NULL) {
	guint8 data[128];
	if (fread(data, 128, 1, f) == 1) {
	  gcry_mpi_scan(&game_modulus, GCRYMPI_FMT_USG, data, 64, NULL);
	  if (game_modulus) {
	    gcry_mpi_scan(&game_exponent, GCRYMPI_FMT_USG, data+64, 64, NULL);
	  }
	}
	fclose(f);
      }
    }
  }
#endif
}

static void
urulive_init_protocol(void) {
  fragment_table_init(&urutcp_fragment_table);
  gameIDmap =
    se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "gametype gameid");
#ifdef HAVE_LIBGCRYPT
  /* I'm not too worried about gcrypt version, but this function is supposed
     to be called first if initialization has not already been performed,
     so... */
  gcry_check_version(NULL);
  if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
    /* this is what packet-ipsec.c does */
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  }
#endif
}

/* Register the protocol with Wireshark */
void
proto_register_urulive(void)
{
  module_t *uru_module;

  /* Register the protocol name and description */
  if (proto_urulive == -1) {
    proto_urulive = proto_register_protocol (
			"UruLive Protocol",		/* name */
			"UruLive",			/* short name */
			"urulive"			/* abbrev */
			);
  }

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_urulive, hf_live, array_length(hf_live));
  proto_register_subtree_array(ett_live, array_length(ett_live));


  /* Register preferences module (See Section 2.6 for more on preferences) */
  uru_module = prefs_register_protocol(proto_urulive,
				       proto_reg_handoff_urulive);
  prefs_register_uint_preference(uru_module, "live_port",
				 "Uru Live TCP Port",
				 "Set the TCP port number for Uru Live "
				 "(if other than the default of 14617).",
				 10,
				 &global_urulive_port);
  prefs_register_bool_preference(uru_module, "desegment",
				 "Reassemble Uru Live messages spanning "
				 "multiple TCP segments",
				 "Whether the Uru Live dissector should "
				 "reassemble messages spanning multiple TCP "
				 "segments.",
				 &global_urulive_desegment);
  prefs_register_bool_preference(uru_module, "show_control",
				 "Show TCP info",
				 "Whether to display the TCP control "
				 "information (seq. no, ack, win, etc.) "
				 "in the summary.",
				 &global_urulive_showtcp);
  prefs_register_bool_preference(uru_module, "detect_version",
				 "Detect version",
				 "Whether to attempt to auto-detect protocol "
				 "version.",
				 &global_urulive_detect_version);
  prefs_register_bool_preference(uru_module, "is_pre4",
				 "Protocol is pre-Live 4",
				 "Whether to assume the protocol is pre- or "
				 "post- Live 4.",
				 &global_urulive_is_pre4);
  prefs_register_bool_preference(uru_module, "is_encrypted",
				 "Encryption is in use",
				 "Whether to assume the encryption is being "
				 "used.",
				 &global_urulive_is_encrypted);
  prefs_register_bool_preference(uru_module, "is_v1",
				 "Protocol is pre-renumbering",
				 "Whether to assume the protocol is pre- or "
				 "post- renumbering (Live 7?).",
				 &global_urulive_is_v1);
  prefs_register_bool_preference(uru_module, "is_pre9",
				 "Protocol is pre-Live 9",
				 "Whether to assume the protocol is pre- or "
				 "post- Live 9.",
				 &global_urulive_is_pre9);
  prefs_register_bool_preference(uru_module, "decrypt",
				 "Decrypt traffic",
				 "Whether to attempt to decrypt Auth and "
				 "Game server traffic.",
				 &global_urulive_decrypt);
  prefs_register_string_preference(uru_module, "keys",
				   "Encryption keys",
				   "A comma-separated list of encryption keys "
				   "expressed as portnum=<7 bytes in hex>.",
				   &global_urulive_keys);
#ifdef HAVE_LIBGCRYPT
  prefs_register_bool_preference(uru_module, "private_keys",
				 "Use D-H private keys",
				 "Whether to compute the RC4 keys from the "
				 "provided key files (overrides other key "
				 "choices).",
				 &global_urulive_use_private_keys);
#else
  /* we still register the preference so it is kept in the preferences
     file, and won't generate errors, between builds with and without
     gcrypt */
  prefs_register_bool_preference(uru_module, "private_keys",
				 "Use D-H private keys (IGNORED)",
				 "This option is ignored; Wireshark must "
				 "be compiled with ligbcrypt to use this "
				 "functionality.",
				 &global_urulive_use_private_keys);
#endif
  prefs_register_string_preference(uru_module, "auth_key_file",
				   "Auth server private key file", "",
				   &global_urulive_auth_file);
  prefs_register_string_preference(uru_module, "game_key_file",
				   "Game server private key file", "",
				   &global_urulive_game_file);

  /* Register protocol init routine */
  register_init_routine(urulive_init_protocol);
}


#ifdef DEVELOPMENT
/* this function is mostly for development; it decrypts un-reassembled
   data */
static void
uru_maybe_decrypt(tvbuff_t *tvb, int offset, int len, packet_info *pinfo,
		  proto_tree *tree, guint32 seq) {
  if (tree
      && live_conv->is_encrypted
      && ((isclient && live_conv->c2s_crypt_zero <= seq)
	  || (!isclient && live_conv->s2c_crypt_zero <= seq))) {
    guint8 *newbuf;
    tvbuff_t *ntvb;
    guint32 port;
    struct rc4_key *key;

    port = (isclient ? pinfo->srcport : pinfo->destport);
    key = find_rc4_key(port);
    if (!global_urulive_decrypt || !key
	|| (isclient && live_conv->c2s_next_state.seq == 0)
	|| (!isclient && live_conv->s2c_next_state.seq == 0)) {
      /* we can't decrypt this */
      return;
    }
    newbuf = tvb_memdup(tvb, offset, len);
    urulive_decrypt(seq, FALSE, newbuf, len);
    ntvb = tvb_new_real_data(newbuf, len, len);
    tvb_set_child_real_data_tvbuff(tvb, ntvb);
    tvb_set_free_cb(ntvb, g_free);
    add_new_data_source(pinfo, ntvb, "Decrypted Data");
  }
}
#endif

static void
call_uru_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		   gboolean set_info_column, int packet_len, guint32 seq)
{
  if (set_info_column) {
    /* Add to the summary: do it here to get full packet length. A side effect
       is that now all message info will be listed, not just the last
       message's, which I'd been thinking about doing anyway... If it gets
       too cluttery we can revisit it. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "UruLive");
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
      if (!global_urulive_showtcp) {
	col_clear(pinfo->cinfo, COL_INFO);
      }
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%u->%u (%u)",
			  pinfo->srcport, pinfo->destport, packet_len);
    }
  }

    /*
     * Dissect the PDU.
     *
     * Catch the ReportedBoundsError exception; if this particular message
     * happens to get a ReportedBoundsError exception, that doesn't mean
     * that we should stop dissecting PDUs within this frame or chunk of
     * reassembled data.
     *
     * If it gets a BoundsError, we can stop, as there's nothing more to
     * see, so we just re-throw it.
     */

		  TRY {
		    dissect_urulive_message(tvb, pinfo, tree, seq);
		  }
		  CATCH(BoundsError) {
		    RETHROW;
		  }
		  CATCH(ReportedBoundsError) {
#ifndef _WIN32
		    show_reported_bounds_error(tvb, pinfo, tree);
#else
		    /* show_reported_bounds_error is not exported
		       in libethereal.dll, and while this is not
		       right (affects whole packet, not message)
		       it at least compiles... */
		    RETHROW;
#endif
		  }
		  ENDTRY;
}

/* 
 * The following desegmentation code is based very heavily on desegment_tcp()
 * and tcp_dissect_pdus() from packet-tcp.c.
 */
#define LT_SEQ(x, y) ((gint32)((x) - (y)) < 0)

static void
desegment_urutcp(tvbuff_t *tvb, packet_info *pinfo,
		 proto_tree *tree, emem_tree_t *multisegment_pdus)
{
	struct tcpinfo *tcpinfo;
	fragment_data *ipfd_head;
	gboolean called_dissector;
	int another_pdu_follows;
	gint nbytes;
	proto_item *item;
	proto_item *frag_tree_item;
	struct tcp_multisegment_pdu *msp;

	int offset = 0;
	guint32 seq, nxtseq;
	tvbuff_t *next_tvb;
	guint new_len;
	gboolean some_dissected = FALSE;
	guint length_remaining;

	tcpinfo = pinfo->private_data;
	seq = tcpinfo->seq;
	nxtseq = tcpinfo->nxtseq;
again:
	ipfd_head=NULL;
	called_dissector = FALSE;
	another_pdu_follows = 0;
	msp=NULL;


	length_remaining = tvb_ensure_length_remaining(tvb, offset);

	/* find the most previous PDU starting before this sequence number */
	msp=se_tree_lookup32_le(multisegment_pdus, seq-1);
	if(msp && msp->seq<=seq && msp->nxtpdu>seq){
		guint len;

		if(!pinfo->fd->flags.visited){
			msp->last_frame=pinfo->fd->num;
			msp->last_frame_time=pinfo->fd->abs_ts;
		}

		/* OK, this PDU was found, which means the segment continues
		   a higher-level PDU and that we must desegment it.
		*/
		len=MIN(nxtseq, msp->nxtpdu) - seq;
		len=MIN(len, length_remaining);
		ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
			urutcp_fragment_table,
			seq - msp->seq,
			len,
			(LT_SEQ (nxtseq,msp->nxtpdu)) );
		/* if we didnt consume the entire segment there is another pdu
		 * starting beyong the end of this one 
		 */
		if(msp->nxtpdu<nxtseq && len>0){
			another_pdu_follows=len;
		}
	} else {
		/* This segment was not found in our table, so it doesn't
		   contain a continuation of a higher-level PDU.
		   Call the normal subdissector.
		*/

		/* see if it is long enough */
		new_len = get_urulive_message_len(NULL,
						  pinfo, tvb, offset, seq);
		if ((int)new_len > tvb_reported_length_remaining(tvb, offset)) {
			int len;

			if (!pinfo->fd->flags.visited) {
			  /* from pdu_store_sequencenumber_of_next_pdu */
			  msp=se_alloc(sizeof(struct tcp_multisegment_pdu));
			  msp->nxtpdu=seq+new_len;
			  msp->seq=seq;
			  msp->first_frame=pinfo->fd->num;
			  msp->last_frame=pinfo->fd->num;
			  msp->last_frame_time=pinfo->fd->abs_ts;
			  se_tree_insert32(multisegment_pdus,
					   seq, (void *)msp);

			  len=MIN(nxtseq - seq, length_remaining);

			  /* add this segment as the first one for this new pdu */
			  fragment_add(tvb, offset, pinfo, msp->first_frame,
				       urutcp_fragment_table, 0,
				       len,
				       LT_SEQ(nxtseq, msp->nxtpdu));
			}
		}
		else {
		  /* call dissector */
		  guint length;

		  if (seq+new_len < nxtseq) {
		    another_pdu_follows = new_len;
		  }

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the PDU.
     *
     * XXX - if reassembly isn't enabled. the subdissector will throw a
     * BoundsError exception, rather than a ReportedBoundsError exception.
     * We really want a tvbuff where the length is "length", the reported
     * length is "plen", and the "if the snapshot length were infinite"
     * length is the minimum of the reported length of the tvbuff handed
     * to us and "plen", with a new type of exception thrown if the offset
     * is within the reported length but beyond that third length, with
     * that exception getting the "Unreassembled Packet" error.
     */

		  length = tvb_ensure_length_remaining(tvb, offset);
		  if (length > new_len)
		    length = new_len;
		  next_tvb = tvb_new_subset(tvb, offset, length, new_len);

		  call_uru_dissector(next_tvb, pinfo, tree, !some_dissected,
				     tvb_reported_length_remaining(tvb, 0),
				     seq);

		  called_dissector = TRUE;
		  some_dissected = TRUE;

		}

		/* Either no desegmentation is necessary, or this is
		   segment contains the beginning but not the end of
		   a higher-level PDU and thus isn't completely
		   desegmented.
		*/
		ipfd_head = NULL;
	}


	/* is it completely desegmented? */
	if(ipfd_head){
		/*
		 * Yes, we think it is.
		 * We only call subdissector for the last segment.
		 * Note that the last segment may include more than what
		 * we needed.
		 */
		if(ipfd_head->reassembled_in==pinfo->fd->num){
			/*
			 * OK, this is the last segment.
			 * Let's call the subdissector with the desegmented
			 * data.
			 */

			/* create a new TVB structure for desegmented data */
			next_tvb = tvb_new_real_data(ipfd_head->data,
					ipfd_head->datalen, ipfd_head->datalen);

			/* add this tvb as a child to the original one */
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);

			/* see if it really is long enough */
			new_len = get_urulive_message_len(NULL,
							  pinfo, next_tvb, 0,
							  msp->seq);
			if (new_len == ipfd_head->datalen) {
			  /* call dissector */

				/*
				 * The subdissector thought it was completely
				 * desegmented (although the stuff at the
				 * end may, in turn, require desegmentation),
				 * so we show a tree with all segments.
				 */
				show_fragment_tree(ipfd_head, &uru_frag_items,
					tree, pinfo, next_tvb, &frag_tree_item);

			  /* add desegmented data to the data source list */
			  add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

			  call_uru_dissector(next_tvb, pinfo, tree,
					!some_dissected,
					tvb_reported_length_remaining(tvb, 0),
					msp->seq);

			  called_dissector = TRUE;
			  some_dissected = TRUE;
			}
			else if (new_len < ipfd_head->datalen) {
			  DISSECTOR_ASSERT_NOT_REACHED();
			}
			else {
			  fragment_set_partial_reassembly(pinfo,msp->first_frame,urutcp_fragment_table);
			  msp->nxtpdu += new_len - ipfd_head->datalen;

			  if (another_pdu_follows) {
			    seq += another_pdu_follows;
			    offset += another_pdu_follows;
			    goto again;
			  }
			  else {
			    /* here, the whole packet was consumed */
			  }
			}
		}
	}

	if (!called_dissector) {
		if (ipfd_head != NULL && ipfd_head->reassembled_in != 0 &&
		    !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
			/*
			 * We know what frame this PDU is reassembled in;
			 * let the user know.
			 */
			item=proto_tree_add_uint(tree, hf_uru_reassembled_in,
			    tvb, 0, 0, ipfd_head->reassembled_in);
			PROTO_ITEM_SET_GENERATED(item);
		}

		/*
		 * Either we didn't call the subdissector at all (i.e.,
		 * this is a segment that contains the middle of a
		 * higher-level PDU, but contains neither the beginning
		 * nor the end), or the subdissector couldn't dissect it
		 * all, as some data was missing (i.e., it set
		 * "pinfo->desegment_len" to the amount of additional
		 * data it needs).
		 */
		if (!some_dissected) {
			/*
			 * It couldn't, in fact, dissect any of it (the
			 * first byte it couldn't dissect is at an offset
			 * of "pinfo->desegment_offset" from the beginning
			 * of the payload, and that's 0).
			 * Just mark this as TCP.
			 */
			if (!global_urulive_showtcp
			    && check_col(pinfo->cinfo, COL_INFO)){
				col_set_str(pinfo->cinfo, COL_INFO, "[TCP segment of a reassembled PDU]");
			}
		}

		/*
		 * Show what's left in the packet as just raw TCP segment
		 * data.
		 * XXX - remember what protocol the last subdissector
		 * was, and report it as a continuation of that, instead?
		 */
		nbytes = tvb_reported_length_remaining(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, -1,
		    "TCP segment data (%u byte%s)", nbytes,
		    plurality(nbytes, "", "s"));
#ifdef DEVELOPMENT
		uru_maybe_decrypt(tvb, offset, nbytes, pinfo, tree, seq);
#endif
	}

	if (another_pdu_follows) {
		offset += another_pdu_follows;
		seq += another_pdu_follows;
		goto again;
	}
}
