/* 
   Please note, this file is meant to #included, one time only, in the
   main packet-uru.c file.  It should not be compiled standalone.
   This file exists to preserve my sanity while writing the dissectors,
   because I spend a lot of time changing the contents of the header
   fields around (since I am not working with a documented protocol and
   cannot just list them up front).
*/

/*
 * uru-hf.c
 * The hf_register_info array for the Uru protocol.
 *
 * Copyright (C) 2005-2006  The Alcugs Project Server Team
 * Copyright (C) 2006-2010  a'moaca'
 *
 * $Id$
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

/* "UU transport layer" fields */
static int hf_uru_incomplete_dissection = -1;
static int hf_uru_dissection_error = -1;
static int hf_uru_header = -1;
static int hf_uru_flag = -1;
static int hf_uru_validation_type = -1;
static int hf_uru_checksum = -1;
static int hf_uru_packetnum = -1;
static int hf_uru_msgtype = -1;
static int hf_uru_unkA = -1;
static int hf_uru_fragnum = -1;
static int hf_uru_msgnum = -1;
static int hf_uru_fragct = -1;
static int hf_uru_unkB = -1;
static int hf_uru_fragack = -1;
static int hf_uru_lastack = -1;
static int hf_uru_msglen = -1;
static int hf_uru_bandwidth = -1;
static int hf_uru_nego_ts = -1;
static int hf_uru_nego_sec = -1;
static int hf_uru_nego_usec = -1;
static int hf_uru_ack_frn = -1;
static int hf_uru_ack_sn = -1;
static int hf_uru_ack_frnf = -1;
static int hf_uru_ack_snf = -1;
static int hf_uru_ack_zero = -1;
static int hf_uru_ack = -1;
static int hf_uru_cmd = -1;
static int hf_uru_flags = -1;
static int hf_uru_flags_ts = -1;
static int hf_uru_flags_notify = -1;
static int hf_uru_flags_ip = -1;
static int hf_uru_flags_firewalled = -1;
static int hf_uru_flags_X = -1;
static int hf_uru_flags_bcast = -1;
static int hf_uru_flags_statereq = -1;
static int hf_uru_flags_ki = -1;
static int hf_uru_flags_avstate = -1;
static int hf_uru_flags_guid = -1;
static int hf_uru_flags_directed = -1;
static int hf_uru_flags_version = -1;
static int hf_uru_flags_custom = -1;
static int hf_uru_flags_ack = -1;
static int hf_uru_flags_sid = -1;
static int hf_uru_flags_p2p = -1;
static int hf_uru_flags_unk = -1;
static int hf_uru_version = -1;
static int hf_uru_maxversion = -1;
static int hf_uru_minversion = -1;
static int hf_uru_ts = -1;
static int hf_uru_ts_sec = -1;
static int hf_uru_ts_usec = -1;
static int hf_uru_X = -1;
static int hf_uru_KI = -1;
static int hf_uru_GUID = -1;
static int hf_uru_IPaddr = -1;
static int hf_uru_port = -1;
static int hf_uru_sid = -1;
static int hf_uru_isfrag = -1;
static int hf_uru_msgbody = -1;

/* netMsg fields */
static int hf_uru_age_flags = -1;
static int hf_uru_age_contents = -1;
static int hf_uru_age_cfname = -1;
static int hf_uru_age_ciname = -1;
static int hf_uru_age_cguid = -1;
static int hf_uru_age_cuname = -1;
static int hf_uru_age_cinstance = -1;
static int hf_uru_age_cdname = -1;
static int hf_uru_age_clang = -1;
static int hf_uru_age_cunk = -1;
static int hf_uru_age_fname = -1;
static int hf_uru_age_iname = -1;
static int hf_uru_age_guid = -1;
static int hf_uru_age_uname = -1;
static int hf_uru_age_instance = -1;
static int hf_uru_age_dname = -1;
static int hf_uru_age_lang = -1;
static int hf_uru_age_rules = -1;
static int hf_uru_age_unk1 = -1;
static int hf_uru_age_spawncts = -1;
static int hf_uru_age_spawnpt = -1;
static int hf_uru_age_linkpt = -1;
static int hf_uru_age_camera = -1;
static int hf_uru_age_unk2 = -1;
static int hf_uru_age_extra = -1;
static int hf_uru_obj_exists = -1;
static int hf_uru_obj = -1;
static int hf_uru_obj_flags = -1;
static int hf_uru_obj_pageid = -1;
static int hf_uru_obj_pagetype = -1;
static int hf_uru_obj_extra = -1;
static int hf_uru_obj_type = -1;
static int hf_uru_obj_name = -1;
static int hf_uru_obj_index = -1;
static int hf_uru_obj_clientid = -1;
static int hf_uru_subobj_exists = -1;
static int hf_uru_subobj = -1;
static int hf_uru_subobj_flags = -1;
static int hf_uru_subobj_pageid = -1;
static int hf_uru_subobj_pagetype = -1;
static int hf_uru_subobj_extra = -1;
static int hf_uru_subobj_type = -1;
static int hf_uru_subobj_name = -1;
static int hf_uru_subobj_index = -1;
static int hf_uru_subobj_clientid = -1;
static int hf_uru_node_trackid = -1;

/* fields specific to certain netMsgs */
static int hf_uru_sdl_uncsize = -1;
static int hf_uru_sdl_cflag = -1;
static int hf_uru_sdl_sdllen = -1;
static int hf_uru_sdl_sdlversion = -1;
static int hf_uru_sdl_sdlname = -1;
static int hf_uru_sdl_eflag = -1;
static int hf_uru_sdl_unk6 = -1;
static int hf_uru_sdl_name = -1;
static int hf_uru_sdl_sdlct = -1;
static int hf_uru_sdl_sub = -1;
static int hf_uru_sdl_sdlsct = -1;
static int hf_uru_sdl_tagflag = -1;
static int hf_uru_sdl_stbzero = -1;
static int hf_uru_sdl_tagstring = -1;
static int hf_uru_sdl_entryflags = -1;
static int hf_uru_sdl_timestamp = -1;
static int hf_uru_sdl_ts_sec = -1;
static int hf_uru_sdl_ts_usec = -1;
static int hf_uru_sdl_varidx = -1;
static int hf_uru_sdl_arrct = -1;
static int hf_uru_sdl_val_default = -1;
static int hf_uru_sdl_val_arr = -1;
static int hf_uru_sdl_val_int = -1;
static int hf_uru_sdl_val_float = -1;
static int hf_uru_sdl_val_bool = -1;
static int hf_uru_sdl_val_byte = -1;
static int hf_uru_sdl_val_short = -1;
static int hf_uru_sdl_val_str = -1;
static int hf_uru_sdl_val_obj = -1;
static int hf_uru_sdl_val_time = -1;
static int hf_uru_sdl_val_sec = -1;
static int hf_uru_sdl_val_usec = -1;
static int hf_uru_sdl_val_x = -1;
static int hf_uru_sdl_val_y = -1;
static int hf_uru_sdl_val_z = -1;
static int hf_uru_sdl_val_3tuple = -1;
static int hf_uru_sdl_val_qa = -1;
static int hf_uru_sdl_val_qb = -1;
static int hf_uru_sdl_val_qc = -1;
static int hf_uru_sdl_val_qd = -1;
static int hf_uru_sdl_val_quat = -1;
static int hf_uru_sdl_val_r = -1;
static int hf_uru_sdl_val_g = -1;
static int hf_uru_sdl_val_b = -1;
static int hf_uru_sdl_val_clr = -1;
static int hf_uru_sdl_sub_ct = -1;
static int hf_uru_sdl_sub_unk = -1;
/* following four are mostly obsolete */
static int hf_uru_sdl_phys_mgr = -1;
static int hf_uru_sdl_cl_linkeff = -1;
static int hf_uru_sdl_cl_item = -1;
static int hf_uru_sdl_morph = -1;
static int hf_uru_sdl_unk01 = -1;
static int hf_uru_sdl_unk02 = -1;
static int hf_uru_sdl_endthing = -1;
static int hf_uru_join_unkflag = -1;
static int hf_uru_leave_reason = -1;
static int hf_uru_term_reason = -1;
static int hf_uru_ping_mtime = -1;
static int hf_uru_ping_dest = -1;
static int hf_uru_auth_login = -1;
static int hf_uru_auth_maxpacket = -1;
static int hf_uru_auth_release = -1;
static int hf_uru_auth_resp = -1;
static int hf_uru_auth_hash = -1;
static int hf_uru_auth_sguid = -1;
static int hf_uru_plist_ct = -1;
static int hf_uru_plist = -1;
static int hf_uru_plist_ki = -1;
static int hf_uru_plist_name = -1;
static int hf_uru_plist_flags = -1;
static int hf_uru_plist_url = -1;
static int hf_uru_setact_name = -1;
static int hf_uru_setact_code = -1;
static int hf_uru_findrply_unk1f = -1;
static int hf_uru_findrply_name = -1;
static int hf_uru_findrply_srvtype = -1;
static int hf_uru_findrply_server = -1;
static int hf_uru_findrply_port = -1;
static int hf_uru_findrply_guid = -1;
static int hf_uru_pageroom_format = -1;
static int hf_uru_pageroom_pageid = -1;
static int hf_uru_pageroom_pagetype = -1;
static int hf_uru_pageroom_pagename = -1;
static int hf_uru_pageroom_page = -1;
static int hf_uru_groupown_mask = -1;
static int hf_uru_groupown_pageid = -1;
static int hf_uru_groupown_pagetype = -1;
static int hf_uru_groupown_unk0 = -1;
static int hf_uru_groupown_flags = -1;
static int hf_uru_loadclone_unk1 = -1;
static int hf_uru_loadclone_unk2 = -1;
static int hf_uru_loadclone_sublen = -1;
static int hf_uru_loadclone_subtype = -1;
static int hf_uru_loadclone_subunk0 = -1;
static int hf_uru_loadclone_subunk1 = -1;
static int hf_uru_loadclone_netmgrexists = -1;
static int hf_uru_loadclone_netmgr = -1;
static int hf_uru_loadclone_subunk4 = -1;
static int hf_uru_loadclone_subunk5 = -1;
static int hf_uru_loadclone_subunk6 = -1;
static int hf_uru_loadclone_avmgrexists = -1;
static int hf_uru_loadclone_avmgr = -1;
static int hf_uru_loadclone_id = -1;
static int hf_uru_loadclone_parentid = -1;
static int hf_uru_loadclone_subunk11 = -1;
static int hf_uru_loadclone_subpage = -1;
static int hf_uru_loadclone_subctype = -1;
static int hf_uru_loadclone_subunk13 = -1;
static int hf_uru_loadclone_subexists = -1;
static int hf_uru_loadclone_subobj = -1;
static int hf_uru_loadclone_subunk13a = -1;
static int hf_uru_loadclone_unk3 = -1;
static int hf_uru_loadclone_unk4 = -1;
static int hf_uru_loadclone_page = -1;
static int hf_uru_loadclone_init = -1;
static int hf_uru_ppage_page = -1;
static int hf_uru_gsreq_ct = -1;
static int hf_uru_gsreq_pageid = -1;
static int hf_uru_gsreq_pagetype = -1;
static int hf_uru_gsreq_name = -1;
static int hf_uru_stsent_num = -1;
static int hf_uru_mlist_ct = -1;
static int hf_uru_mlist_unkflags = -1;
static int hf_uru_mlist_cts = -1;
static int hf_uru_mlist_ki = -1;
static int hf_uru_mlist_name = -1;
static int hf_uru_mlist_buildtype = -1;
static int hf_uru_mlist_ip = -1;
static int hf_uru_mlist_port = -1;
static int hf_uru_mlist_player = -1;
static int hf_uru_mlist_vis = -1;
static int hf_uru_mlist_key = -1;
static int hf_uru_mlist_page = -1;
static int hf_uru_timeout = -1;
static int hf_uru_test_flag1 = -1;
static int hf_uru_test_unk1 = -1;
static int hf_uru_test_msglen = -1;
static int hf_uru_test_type = -1;
static int hf_uru_test_unk3 = -1;
static int hf_uru_test_state1 = -1;
static int hf_uru_test_state = -1;
static int hf_uru_test_flag2 = -1;
static int hf_uru_test_state2 = -1;
static int hf_uru_test_endthing = -1;
static int hf_uru_voice_unk0 = -1;
static int hf_uru_voice_unk1 = -1;
static int hf_uru_voice_msglen = -1;
static int hf_uru_voice_data = -1;
static int hf_uru_voice_recipct = -1;
static int hf_uru_voice_recip = -1;
static int hf_uru_vault_cmd = -1;
static int hf_uru_vault_task = -1;
static int hf_uru_vault_result = -1;
static int hf_uru_vault_cflag = -1;
static int hf_uru_vault_uncsize = -1;
static int hf_uru_vault_msglen = -1;
static int hf_uru_vault_itemct = -1;
static int hf_uru_vault_id = -1;
static int hf_uru_vault_dtype = -1;
static int hf_uru_vault_cgv_format = -1;
static int hf_uru_vault_cgv_int = -1;
static int hf_uru_vault_cgv_str = -1;
static int hf_uru_vault_cgv_ts = -1;
static int hf_uru_vault_cs_len = -1;
static int hf_uru_vault_cs_stream = -1;
static int hf_uru_vault_nego_ct4 = -1;
static int hf_uru_vault_nego_ct2 = -1;
static int hf_uru_vault_nego_node = -1;
static int hf_uru_vault_nego_ref = -1;
static int hf_uru_vault_nego_nodeidx = -1;
static int hf_uru_vault_sguid = -1;
static int hf_uru_vault_ref_id1 = -1;
static int hf_uru_vault_ref_id2 = -1;
static int hf_uru_vault_ref_id3 = -1;
static int hf_uru_vault_ref_flag = -1;
static int hf_uru_vault_node_masklen = -1;
static int hf_uru_vault_node_mask1 = -1;
static int hf_uru_vault_node_mask2 = -1;
static int hf_uru_vault_node_index = -1;
static int hf_uru_vault_node_type = -1;
static int hf_uru_vault_node_perm = -1;
static int hf_uru_vault_node_owner = -1;
static int hf_uru_vault_node_unk1 = -1;
static int hf_uru_vault_node_ts = -1;
static int hf_uru_vault_node_sec = -1;
static int hf_uru_vault_node_usec = -1;
static int hf_uru_vault_node_id1 = -1;
static int hf_uru_vault_node_ts2 = -1;
static int hf_uru_vault_node_sec2 = -1;
static int hf_uru_vault_node_usec2 = -1;
static int hf_uru_vault_node_ts3 = -1;
static int hf_uru_vault_node_sec3 = -1;
static int hf_uru_vault_node_usec3 = -1;
static int hf_uru_vault_node_agename = -1;
static int hf_uru_vault_node_hexguid = -1;
static int hf_uru_vault_node_ftype = -1;
static int hf_uru_vault_node_dist = -1;
static int hf_uru_vault_node_elev = -1;
static int hf_uru_vault_node_unk5 = -1;
static int hf_uru_vault_node_id2 = -1;
static int hf_uru_vault_node_unk7 = -1;
static int hf_uru_vault_node_unk8 = -1;
static int hf_uru_vault_node_unk9 = -1;
static int hf_uru_vault_node_entryname = -1;
static int hf_uru_vault_node_subentry = -1;
static int hf_uru_vault_node_ownername = -1;
static int hf_uru_vault_node_guid = -1;
static int hf_uru_vault_node_str1 = -1;
static int hf_uru_vault_node_str2 = -1;
static int hf_uru_vault_node_avname = -1;
static int hf_uru_vault_node_uid = -1;
static int hf_uru_vault_node_entry = -1;
static int hf_uru_vault_node_entry2 = -1;
static int hf_uru_vault_node_dsize = -1;
static int hf_uru_vault_node_data = -1;
static int hf_uru_vault_node_d2size = -1;
static int hf_uru_vault_node_data2 = -1;
static int hf_uru_vault_node_blob1 = -1;
static int hf_uru_vault_node_blob2 = -1;
static int hf_uru_vault_ctx16 = -1;
static int hf_uru_vault_ctx = -1;
static int hf_uru_vault_res = -1;
static int hf_uru_vault_mgr = -1;
static int hf_uru_vault_vn = -1;
static int hf_uru_create_avname = -1;
static int hf_uru_create_gender = -1;
static int hf_uru_create_fname = -1;
static int hf_uru_create_passkey = -1;
static int hf_uru_create_unk1 = -1;
static int hf_uru_created_resp = -1;
static int hf_uru_delete_unk1 = -1;
static int hf_uru_gamemsg_uncsize = -1;
static int hf_uru_gamemsg_cflag = -1;
static int hf_uru_gamemsg_msglen = -1;
static int hf_uru_gamemsg_type = -1;
static int hf_uru_gamemsg_subobjct = -1;
static int hf_uru_gamemsg_unk2 = -1;
static int hf_uru_gamemsg_unk3 = -1;
static int hf_uru_gamemsg_flags = -1;
static int hf_uru_kimsg_unk6 = -1;
static int hf_uru_kimsg_sender = -1;
static int hf_uru_kimsg_senderKI = -1;
static int hf_uru_kimsg_msg = -1;
static int hf_uru_kimsg_chatflags = -1;
static int hf_uru_kimsg_private = -1;
static int hf_uru_kimsg_admin = -1;
static int hf_uru_kimsg_flag04 = -1;
static int hf_uru_kimsg_interage = -1;
static int hf_uru_kimsg_status = -1;
static int hf_uru_kimsg_neighbors = -1;
static int hf_uru_kimsg_translate = -1;
static int hf_uru_kimsg_flag80 = -1;
static int hf_uru_kimsg_channel = -1;
static int hf_uru_kimsg_unk7 = -1;
static int hf_uru_kimsg_unk8 = -1;
static int hf_uru_kimsg_unk9 = -1;
static int hf_uru_linkmsg_unk2 = -1;
static int hf_uru_linkmsg_msglen = -1;
static int hf_uru_linkmsg_str = -1;
static int hf_uru_linkmsg_unk4 = -1;
static int hf_uru_linkmsg_unk5 = -1;
static int hf_uru_linkmsg_unk6 = -1;
static int hf_uru_linkmsg_unk7 = -1;
static int hf_uru_linkmsg_unk8 = -1;
static int hf_uru_linkmsg_unk9 = -1;
static int hf_uru_linkmsg_reqki = -1;
static int hf_uru_notify_unk2 = -1;
static int hf_uru_notify_state = -1;
static int hf_uru_notify_unk4 = -1;
static int hf_uru_notify_eventct = -1;
static int hf_uru_notify_event0 = -1;
static int hf_uru_notify_objexists = -1;
static int hf_uru_notify_obj = -1;
static int hf_uru_notify_offer_event2 = -1;
static int hf_uru_notify_offer_event3 = -1;
static int hf_uru_notify_multistg_num = -1;
static int hf_uru_notify_multistg_event = -1;
static int hf_uru_notify_picked_event3 = -1;
static int hf_uru_notify_picked_x = -1;
static int hf_uru_notify_picked_y = -1;
static int hf_uru_notify_picked_z = -1;
static int hf_uru_notify_coll_event1 = -1;
static int hf_uru_notify_contain_ex = -1;
static int hf_uru_notify_contain_event2s = -1;
static int hf_uru_notify_contain_event2 = -1;
static int hf_uru_notify_var_var = -1;
static int hf_uru_notify_var_type = -1;
static int hf_uru_notify_var_event3f = -1;
static int hf_uru_notify_var_event3o = -1;
static int hf_uru_notify_var_event4 = -1;
static int hf_uru_notify_respst_state = -1;
static int hf_uru_notify_facing_event3 = -1;
static int hf_uru_notify_facing_event4 = -1;
static int hf_uru_notify_act_event1 = -1;
static int hf_uru_notify_act_event2 = -1;
static int hf_uru_notify_num13_ki = -1;
static int hf_uru_notify_num13_event2 = -1;
static int hf_uru_iface_unk1 = -1;
static int hf_uru_iface_float = -1;
static int hf_uru_iface_str1 = -1;
static int hf_uru_iface_str2 = -1;
static int hf_uru_iface_str3 = -1;
static int hf_uru_iface_objexists = -1;
static int hf_uru_iface_obj = -1;
static int hf_uru_srply_reply = -1;
static int hf_uru_avstate_flags = -1;
static int hf_uru_avstate_fwd = -1;
static int hf_uru_avstate_back = -1;
static int hf_uru_avstate_right = -1;
static int hf_uru_avstate_left = -1;
static int hf_uru_avstate_sider = -1;
static int hf_uru_avstate_sidel = -1;
static int hf_uru_linkeff_unk0 = -1;
static int hf_uru_linkeff_unk1 = -1;
static int hf_uru_linkeff_objexists = -1;
static int hf_uru_linkeff_obj = -1;
static int hf_uru_linkeff_unk2 = -1;
static int hf_uru_linkeff_effexists = -1;
static int hf_uru_linkeff_eff = -1;
static int hf_uru_clothing_flags = -1;
static int hf_uru_clothing_present = -1;
static int hf_uru_clothing_objexists = -1;
static int hf_uru_clothing_item = -1;
static int hf_uru_clothing_r = -1;
static int hf_uru_clothing_g = -1;
static int hf_uru_clothing_b = -1;
static int hf_uru_clothing_o = -1;
static int hf_uru_clothing_flag = -1;
static int hf_uru_clothing_unk3 = -1;
static int hf_uru_wall_msgtype = -1;
static int hf_uru_wall_unk0 = -1;
static int hf_uru_wall_sstate = -1;
static int hf_uru_wall_nstate = -1;
static int hf_uru_wall_bl = -1;
static int hf_uru_wall_blct = -1;
static int hf_uru_wall_blidx = -1;
static int hf_uru_wall_side = -1;
static int hf_uru_wall_state = -1;
static int hf_uru_warp_matrix = -1;
static int hf_uru_warp_unk = -1;
static int hf_uru_subworld_objexists = -1;
static int hf_uru_subworld_obj = -1;
static int hf_uru_enable_unk0 = -1;
static int hf_uru_enable_unk1 = -1;
static int hf_uru_enable_unk2 = -1;
static int hf_uru_avseek_unk0 = -1;
static int hf_uru_avseek_tox = -1;
static int hf_uru_avseek_toy = -1;
static int hf_uru_avseek_toz = -1;
static int hf_uru_avseek_fmx = -1;
static int hf_uru_avseek_fmy = -1;
static int hf_uru_avseek_fmz = -1;
static int hf_uru_avseek_unk1 = -1;
static int hf_uru_avseek_unk2 = -1;
static int hf_uru_avseek_unk3 = -1;
static int hf_uru_avtask_unk0 = -1;
static int hf_uru_avtask_type = -1;
static int hf_uru_avtask_name = -1;
static int hf_uru_avtask_action = -1;
static int hf_uru_oneshot_unk0 = -1;
static int hf_uru_oneshot_objexists = -1;
static int hf_uru_oneshot_obj = -1;
static int hf_uru_oneshot_unk1 = -1;
static int hf_uru_oneshot_unk2 = -1;
static int hf_uru_oneshot_unk3 = -1;
static int hf_uru_oneshot_unk4 = -1;
static int hf_uru_oneshot_anim = -1;
static int hf_uru_oneshot_unk5 = -1;
static int hf_uru_ctrlevt_unk0 = -1;
static int hf_uru_ctrlevt_unk1 = -1;
static int hf_uru_ctrlevt_unk2 = -1;
static int hf_uru_ctrlevt_unk3 = -1;
static int hf_uru_ctrlevt_unk4 = -1;
static int hf_uru_ctrlevt_unk5 = -1;
static int hf_uru_ctrlevt_unk6 = -1;
static int hf_uru_ctrlevt_cmd = -1;
static int hf_uru_multimod_unk0 = -1;
static int hf_uru_multimod_unk1 = -1;
static int hf_uru_multimod_unk2 = -1;
static int hf_uru_multimod_unk3 = -1;
static int hf_uru_climb_unk0 = -1;
static int hf_uru_climb_unk1 = -1;
static int hf_uru_climb_unk2 = -1;
static int hf_uru_climb_objexists = -1;
static int hf_uru_climb_obj = -1;
static int hf_uru_fakelink_destexists = -1;
static int hf_uru_fakelink_dest = -1;
static int hf_uru_fakelink_objexists = -1;
static int hf_uru_fakelink_obj = -1;
static int hf_uru_brain_unk0 = -1;
static int hf_uru_brain_unk1 = -1;
static int hf_uru_brain_unk2 = -1;
static int hf_uru_brain_unk3 = -1;
static int hf_uru_brain_time = -1;
static int hf_uru_share_unk0 = -1;
static int hf_uru_share_type = -1;
static int hf_uru_share_sharerexists = -1;
static int hf_uru_share_sharer = -1;
static int hf_uru_share_shareeexists = -1;
static int hf_uru_share_sharee = -1;
static int hf_uru_share_unktype = -1;
static int hf_uru_share_unk1 = -1;
static int hf_uru_share_unkflag = -1;
static int hf_uru_share_avmgrexists = -1;
static int hf_uru_share_avmgr = -1;
static int hf_uru_share_bytes = -1;
static int hf_uru_share_stagect = -1;
static int hf_uru_share_stagetype = -1;
static int hf_uru_share_stagename = -1;
static int hf_uru_share_stagebytes = -1;
static int hf_uru_share_fromki = -1;
static int hf_uru_share_stageunk = -1;
static int hf_uru_share_unk2 = -1;
static int hf_uru_share_keyexists = -1;
static int hf_uru_share_key = -1;
static int hf_uru_share_netmgrexists = -1;
static int hf_uru_share_netmgr = -1;
static int hf_uru_share_str0 = -1;
static int hf_uru_share_strc = -1;
static int hf_uru_share_unk4 = -1;
static int hf_uru_share_ki = -1;
static int hf_uru_share_unk5 = -1;
static int hf_uru_avtask_braintype = -1;
static int hf_uru_avtask_brainstage = -1;
static int hf_uru_avtask_brainunk1 = -1;
static int hf_uru_avtask_braintime1 = -1;
static int hf_uru_avtask_braintime2 = -1;
static int hf_uru_avtask_stagect = -1;
static int hf_uru_avtask_stagetype = -1;
static int hf_uru_avtask_stagename = -1;
static int hf_uru_avtask_bytes = -1;
static int hf_uru_avtask_brainunk0 = -1;
static int hf_uru_physical_vx = -1;
static int hf_uru_physical_vy = -1;
static int hf_uru_physical_vz = -1;
static int hf_uru_physical_v = -1;
static int hf_uru_avenable_unk0 = -1;
static int hf_uru_avenable_en = -1;
static int hf_uru_particle_objexists = -1;
static int hf_uru_particle_obj = -1;
static int hf_uru_particle_count = -1;
static int hf_uru_particle_killnum = -1;
static int hf_uru_particle_killtime = -1;
static int hf_uru_particle_killflags = -1;
static int hf_uru_gamemsg_endthing = -1;
static int hf_uru_directed_recipct = -1;
static int hf_uru_directed_recip = -1;
static int hf_uru_pubage_name = -1;
static int hf_uru_pubage_ct = -1;
static int hf_uru_pubage_popct = -1;
static int hf_uru_pubage_pop = -1;
static int hf_uru_python_contents = -1;
static int hf_uru_python_objexists = -1;
static int hf_uru_python_obj = -1;
static int hf_uru_relevance_len1 = -1;
static int hf_uru_relevance_occupied = -1;
static int hf_uru_relevance_occ_ferry = -1;
static int hf_uru_relevance_occ_greatstair = -1;
static int hf_uru_relevance_occ_kahlopub = -1;
static int hf_uru_relevance_occ_courtyard = -1;
static int hf_uru_relevance_occ_takotahalley = -1;
static int hf_uru_relevance_occ_museumalley = -1;
static int hf_uru_relevance_occ_palace01 = -1;
static int hf_uru_relevance_occ_palace02 = -1;
static int hf_uru_relevance_occ_tjunction = -1;
static int hf_uru_relevance_occ_canyon = -1;
static int hf_uru_relevance_occ_concerthall = -1;
static int hf_uru_relevance_occ_bridgestairs = -1;
static int hf_uru_relevance_occ_librarywalk = -1;
static int hf_uru_relevance_occ_librarystairs = -1;
static int hf_uru_relevance_occ_libraryext = -1;
static int hf_uru_relevance_occ_kadishgallery = -1;
static int hf_uru_relevance_occ_mystery = -1;
static int hf_uru_relevance_occ_unknown = -1;
static int hf_uru_relevance_len2 = -1;
static int hf_uru_relevance_interesting = -1;
static int hf_uru_relevance_interesting_ferry = -1;
static int hf_uru_relevance_interesting_greatstair = -1;
static int hf_uru_relevance_interesting_kahlopub = -1;
static int hf_uru_relevance_interesting_courtyard = -1;
static int hf_uru_relevance_interesting_takotahalley = -1;
static int hf_uru_relevance_interesting_museumalley = -1;
static int hf_uru_relevance_interesting_palace01 = -1;
static int hf_uru_relevance_interesting_palace02 = -1;
static int hf_uru_relevance_interesting_tjunction = -1;
static int hf_uru_relevance_interesting_canyon = -1;
static int hf_uru_relevance_interesting_concerthall = -1;
static int hf_uru_relevance_interesting_bridgestairs = -1;
static int hf_uru_relevance_interesting_librarywalk = -1;
static int hf_uru_relevance_interesting_librarystairs = -1;
static int hf_uru_relevance_interesting_libraryext = -1;
static int hf_uru_relevance_interesting_kadishgallery = -1;
static int hf_uru_relevance_interesting_mystery = -1;
static int hf_uru_relevance_interesting_unknown = -1;

/* special cases */
static int hf_uru_cmd_uu = -1;
static int hf_uru_cmd_pots = -1;
static int hf_uru_vault_dtype_uu = -1;
static int hf_uru_vault_dtype_pots = -1;
static int hf_uru_ischat = -1; /* utility value */

/* fields for fragment assembly */
static int hf_uru_fragments = -1;
static int hf_uru_fragment = -1;
static int hf_uru_fragment_overlap = -1;
static int hf_uru_fragment_overlap_conflicts = -1;
static int hf_uru_fragment_multiple_tails = -1;
static int hf_uru_fragment_too_long_fragment = -1;
static int hf_uru_fragment_error = -1;
static int hf_uru_reassembled_in = -1;
#ifdef HAVE_REASSEMBLED_LENGTH
static int hf_uru_reassembled_length = -1;
#endif
#ifdef HAVE_FRAGMENT_COUNT
static int hf_uru_fragment_count = -1;
#endif

static const fragment_items uru_frag_items = {
	/* Fragment subtrees */
	&ett_uru_fragment,
	&ett_uru_fragments,
	/* Fragment fields */
	&hf_uru_fragments,
	&hf_uru_fragment,
	&hf_uru_fragment_overlap,
	&hf_uru_fragment_overlap_conflicts,
	&hf_uru_fragment_multiple_tails,
	&hf_uru_fragment_too_long_fragment,
	&hf_uru_fragment_error,
#ifdef HAVE_FRAGMENT_COUNT
	&hf_uru_fragment_count,
#endif
	/* Reassembled in field */
	&hf_uru_reassembled_in,
#ifdef HAVE_REASSEMBLED_LENGTH
	&hf_uru_reassembled_length,
#endif
	/* Tag */
	"Uru message fragments"
};


static const value_string validtypenames[] = {
  { 0, "none" },
  { 1, "checksum" },
  { 2, "encoded" },
  { 0, NULL }
};

static const value_string messagetypes[] = {
  { 0x80, "Ack" },
  { 0x42, "Negotiation|AckRequired" },
  { 0x00, "NetMsg" },
  { 0x02, "NetMsg|AckRequired" },
  { 0, NULL }
};

static const value_string plNetMsgs[] = {
  { NetMsgPagingRoom, "NetMsgPagingRoom" },
  { NetMsgJoinReq, "NetMsgJoinReq" },
  { NetMsgJoinAck, "NetMsgJoinAck" },
  { NetMsgLeave, "NetMsgLeave" },
  { NetMsgPing, "NetMsgPing" },
  { NetMsgGroupOwner, "NetMsgGroupOwner" },
  { NetMsgGameStateRequest, "NetMsgGameStateRequest" },
  { NetMsgGameMessage, "NetMsgGameMessage" },
  { NetMsgVoice, "NetMsgVoice" },
  { NetMsgTestAndSet, "NetMsgTestAndSet" },
  { NetMsgMembersListReq, "NetMsgMembersListReq" },
  { NetMsgMembersList, "NetMsgMembersList" },
  { NetMsgMemberUpdate, "NetMsgMemberUpdate" },
  { NetMsgCreatePlayer, "NetMsgCreatePlayer" },
  { NetMsgAuthenticateHello, "NetMsgAuthenticateHello" },
  { NetMsgAuthenticateChallenge, "NetMsgAuthenticateChallenge" },
  { NetMsgInitialAgeStateSent, "NetMsgInitialAgeStateSent" },
  { NetMsgVaultTask, "NetMsgVaultTask" },
  { NetMsgAlive, "NetMsgAlive" },
  { NetMsgTerminated, "NetMsgTerminated" },
  { NetMsgSDLState, "NetMsgSDLState" },
  { NetMsgSDLStateBCast, "NetMsgSDLStateBCast" },
  { NetMsgGameMessageDirected, "NetMsgGameMessageDirected" },
  { NetMsgRequestMyVaultPlayerList, "NetMsgRequestMyVaultPlayerList" },
  { NetMsgVaultPlayerList, "NetMsgVaultPlayerList" },
  { NetMsgSetMyActivePlayer, "NetMsgSetMyActivePlayer" },
  { NetMsgPlayerCreated, "NetMsgPlayerCreated" },
  { NetMsgFindAge, "NetMsgFindAge" },
  { NetMsgFindAgeReply, "NetMsgFindAgeReply" },
  { NetMsgDeletePlayer, "NetMsgDeletePlayer" },
  { NetMsgAuthenticateResponse, "NetMsgAuthenticateResponse" },
  { NetMsgAccountAuthenticated, "NetMsgAccountAuthenticated" },
  { NetMsgLoadClone, "NetMsgLoadClone" },
  { NetMsgPlayerPage, "NetMsgPlayerPage" },
  { NetMsgVault, "NetMsgVault" },
  { NetMsgVault2, "NetMsgVault2" },
  { NetMsgSetTimeout, "NetMsgSetTimeout" },
#if 0 /* argggh :( */
  { NetMsgSetTimeout2, "NetMsgSetTimeout2" },
  { NetMsgActivePlayerSet, "NetMsgActivePlayerSet" },
#else
  { NetMsgActivePlayerSet, "NetMsgActivePlayerSet or NetMsgSetTimeout2" },
#endif
  { NetMsgActivePlayerSet2, "NetMsgActivePlayerSet2" },
  /* added here */
#define NetMsgRelevanceRegions plNetMsgRelevanceRegions
  { NetMsgRelevanceRegions, "NetMsgRelevanceRegions" },
#define NetMsgGetPublicAgeList plNetMsgGetPublicAgeList
  { NetMsgGetPublicAgeList, "NetMsgGetPublicAgeList" },
#define NetMsgPublicAgeList plNetMsgPublicAgeList
  { NetMsgPublicAgeList, "NetMsgPublicAgeList" },
#define NetMsgPython plNetMsgPython
  { NetMsgPython, "NetMsgPython" },

  { NetMsgCustomAuthAsk, "NetMsgCustomAuthAsk" },
  { NetMsgCustomAuthResponse, "NetMsgCustomAuthResponse" },
  { NetMsgCustomVaultAskPlayerList, "NetMsgCustomVaultAskPlayerList" },
  { NetMsgCustomVaultPlayerList, "NetMsgCustomVaultPlayerList" },
  { NetMsgCustomVaultCreatePlayer, "NetMsgCustomVaultCreatePlayer" },
  { NetMsgCustomVaultPlayerCreated, "NetMsgCustomVaultPlayerCreated" },
  { NetMsgCustomVaultDeletePlayer, "NetMsgCustomVaultDeletePlayer" },
  { NetMsgCustomPlayerStatus, "NetMsgCustomPlayerStatus" },
  { NetMsgCustomVaultCheckKi, "NetMsgCustomVaultCheckKi" },
  { NetMsgCustomVaultKiChecked, "NetMsgCustomVaultKiChecked" },
  { NetMsgCustomRequestAllPlStatus, "NetMsgCustomRequestAllPlStatus" },
  { NetMsgCustomAllPlayerStatus, "NetMsgCustomAllPlayerStatus" },
  { NetMsgCustomSetGuid, "NetMsgCustomSetGuid" },
  { NetMsgCustomFindServer, "NetMsgCustomFindServer" },
  { NetMsgCustomServerFound, "NetMsgCustomServerFound" },
  { NetMsgCustomForkServer, "NetMsgCustomForkServer" },
  { NetMsgPlayerTerminated, "NetMsgPlayerTerminated" },
  { NetMsgCustomVaultPlayerStatus, "NetMsgCustomVaultPlayerStatus" },
  { NetMsgCustomMetaRegister, "NetMsgCustomMetaRegister" },
  { NetMsgCustomMetaPing, "NetMsgCustomMetaPing" },
  { NetMsgCustomServerVault, "NetMsgCustomServerVault" },
  { NetMsgCustomServerVaultTask, "NetMsgCustomServerVaultTask" },
  { NetMsgCustomSaveGame, "NetMsgCustomSaveGame" },
  { NetMsgCustomLoadGame, "NetMsgCustomLoadGame" },
  { NetMsgCustomCmd, "NetMsgCustomCmd" },
  { 0, NULL }
};

/* actual plNetMessage flags */
#define kHasTimeSent		0x1	/* Alcugs: plNetTimestamp */
#define kHasGameMsgRcvrs	0x2	/* plFlagsMaybeNotify below */
#define kEchoBackToSender	0x4
#define kRequestP2P		0x8
#define kAllowTimeOut		0x10	/* XXX Alcugs: plNetIP */
#define kIndirectMember		0x20	/* Alcugs: plNetFirewalled */
#define kPublicIPClient		0x40
#define kHasContext		0x80
#define kAskVaultForGameState	0x100
#define kHasTransactionID	0x200	/* Alcugs: plNetX */
#define kNewSDLState		0x400	/* Alcugs: plNetBcast */
#define kInitialAgeStateRequest	0x800	/* Alcugs: plNetStateReq */
#define kHasPlayerID		0x1000	/* Alcugs: plNetKi */
#define kUseRelevanceRegions	0x2000	/* plFlagsMaybeAvatarState below */
#define kHasAcctUUID		0x4000	/* Alcugs: plNetGUI */
#define kInterAgeRouting	0x8000	/* Alcugs: plNetDirected */
#define kHasVersion		0x10000	/* Alcugs: plNetVersion */
#define kIsSystemMessage	0x20000	/* Alcugs: plNetCustom */
#define kNeedsReliableSend	0x40000	/* Alcugs: plNetAck */
#define kRouteToAllPlayers	0x80000

static const true_false_string yes_no = {
  "Yes",
  "No"
};

static const value_string authresponses[] = {
  { AAuthSucceeded, "AuthSucceeded" },
  { AAuthHello, "AuthHello" },
  { AProtocolOlder, "ProtocolOlder" },
  { AProtocolNewer, "ProtocolNewer" },
  { AAccountExpired, "AccountExpired" },
  { AAccountDisabled, "AccountDisabled" },
  { AInvalidPasswd, "InvalidPasswd" },
  { AInvalidUser, "InvalidUser" },
  { AHacked, "Hacked (custom)" },
  { ABanned, "Banned (custom)" },
  { 0, NULL }
};

static const value_string leavereasons[] = {
  { RStopResponding, "StopResponding" },
  { RInroute, "Inroute" }, 
  { RArriving, "Arriving" },
  { RJoining, "Joining" },
  { RLeaving, "Leaving" },
  { RQuitting, "Quitting" },
  { RInGame, "InGame (custom)" },
  { 0, NULL }
};

static const value_string termreasons[] = {
  { RUnknown, "Unknown" },
  { RKickedOff, "KickedOff" },
  { RTimedOut, "TimedOut" },
  { RLoggedInElsewhere, "LoggedInElsewhere" },
  { RNotAuthenticated, "NotAuthenticated" },
  { RUnprotectedCCR, "UnprotectedCCR" },
  { RIllegalCCRClient, "IllegalCCRClient" },
  { RHackAttempt, "HackAttempt (custom)" },
  { RUnimplemented, "Unimplemented (custom)" },
  { RParseError, "ParseError (custom)" },
  { 0, NULL }
};

static const value_string destinations[] = {
  { KAgent, "Agent" },
  { KLobby, "Lobby" },
  { KGame, "Game" },
  { KVault, "Vault" },
  { KAuth, "Auth" },
  { KAdmin, "Admin" },
  { KLookup, "Lookup" },
  { KClient, "Client" },
  { KMeta, "Meta (custom)" },
  { KTracking, "Tracking (custom)" }, /* == KLookup */
  { KTest, "Test (custom)" },
  { KData, "Data (custom)" },
  { KProxy, "Proxy (custom)" },
  { KPlFire, "PlFire (custom)" },
  { KBcast, "BCast (custom)" },
  { 0, NULL }
};

static const value_string linkingrules[] = {
  { KBasicLink, "kBasicLink" },
  { KOriginalBook, "kOriginalBook" },
  { KSubAgeBook, "kSubAgeBook" },
  { KOwnedBook, "kOwnedBook" },
  { KVisitBook, "kVisitBook" },
  { KChildAgeBook, "kChildAgeBook" },
  { 0, NULL }
};

static const value_string createresponses[] = {
  { AOK, "OK" },
  { AUnknown, "Unknown" },
  { ANameDoesNotHaveEnoughLetters, "NameDoesNotHaveEnoughLetters" },
  { ANameIsTooShort, "NameIsTooShort" },
  { ANameIsTooLong, "NameIsTooLong" },
  { AInvitationNotFound, "InvitationNotFound" },
  { ANameIsAlreadyInUse, "NameIsAlreadyInUse" },
  { ANameIsNotAllowed, "NameIsNotAllowed" },
  { AMaxNumberPerAccountReached, "MaxNumberPerAccountReached" },
  { AUnspecifiedServerError, "UnspecifiedServerError" },
  { 0, NULL }
};

static const value_string pageflags[] = {
  { 0, "page in" },
  { 1, "page out" },
  { 0, NULL }
};

static const value_string cloneflags[] = {
  { 0, "unload" },
  { 1, "load" },
  { 0, NULL }
};

static const value_string compflags[] = {
#define kCompressionNone 0
  { kCompressionNone, "None" },
#define kCompressionFailed 1
  { kCompressionFailed, "Failed" },
#define kCompressionZlib 2
  { kCompressionZlib, "Zlib" },
#define kCompressionDont 3
  { kCompressionDont, "Don't" },
  { 0, NULL }
};

static const value_string vcompflags[] = {
  { 0x01, "None" },
  { 0x03, "Zlib" },
  { 0, NULL }
};

static const value_string sdlflags[] = {
  { 0x0000, "None" },
  { 0x0001, "Not persistent" },
  { 0, NULL }
};

/* these flags are needed to parse the SDL messages correctly */
#define SDLFlagUnknown01 0x01
#define SDLFlagUnknown02 0x02
#define SDLFlagTimestamp 0x04
#define SDLFlagNoData 0x08
#define SDLFlagDirty 0x10
#define SDLFlagUnknown20 0x20

/* SDL types */
#define SDLTypeINT 0
#define SDLTypeFLOAT 1
#define SDLTypeBOOL 2
#define SDLTypeSTRING32 3
#define SDLTypePLKEY 4
#define SDLTypeCREATABLE 6
#define SDLTypeTIME 8
#define SDLTypeBYTE 9
#define SDLTypeSHORT 10
#define SDLTypeAGETIMEOFDAY 11
#define SDLTypeVECTOR3 50
#define SDLTypePOINT3 51
#define SDLTypeQUATERNION 54
#define SDLTypeRGB8 55

/* flags for NetMsgMemberList and NetMsgMemberUpdate */
#define kAccountUUID 0x0001
#define kPlayerID 0x0002
#define kTempPlayerID 0x0004
#define kCCRLevel 0x0008
#define kProtectedLogin 0x0010
#define kBuildType 0x0020
#define kPlayerName 0x0040
#define kSrcAddr 0x0080
#define kSrcPort 0x0100
#define kReserved 0x0200
#define kClientKey 0x0400

#if 0
/* plInputIfaceMgrMsg flags */
#define kAddInterface
#define kRemoveInterface
#define kEnableClickables
#define kDisableClickables
#define kSetOfferBookMode
#define kClearOfferBookMode
#define kNotifyOfferAccepted
#define kNotifyOfferRejected
#define kNotifyOfferCompleted
#define kDisableAvatarClickable
#define kEnableAvatarClickable
#define kGUIDisableAvatarClickable
#define kGUIEnableAvatarClickable
#define kSetShareSpawnPoint
#endif

/* plAvatarInputStateMsg flags */
#define InputForward 0x0001
#define InputBack 0x0002
#define InputTurnLeft 0x0004
#define InputTurnRight 0x0008
#define InputSidestepLeft 0x0010
#define InputSidestepRight 0x0020
/* ... */

/* chat message flags */
#define kRTChatPrivate 0x01
#define kRTChatAdmin 0x02
#define kRTChatInterAge 0x08
#define kRTChatStatusMsg 0x10
#define kRTChatNeighborsMsg 0x20
#define kRTChatTranslate 0x40

#if 0
/* still need to dissect these */
      /* also need to dissect plAvBrainGenericMsg and plAnimCmdMsg, finish
	 plAvTaskMsg */
        Type: Unknown (0x0458)
        Type: Unknown (0x0459)
        Type: Unknown (0x045e) /* may have to do with infinitely looping scraping noises */ /* plSetNetGroupIDMsg ?!? */
                 tpots 0x045f
#endif
static const value_string typecodes[] = {
  { 0x8000, "No type" },
  { plNetClientMgr, "plNetClientMgr" },
  { plAvatarMgr, "plAvatarMgr" },
  { plLoadAvatarMsg, "plLoadAvatarMsg" },
  { pfKIMsg, "pfKIMsg" },
  { plLinkToAgeMsg, "plLinkToAgeMsg" },
  { plLinkingMgrMsg, "plLinkingMgrMsg" },
  { plNotifyMsg, "plNotifyMsg" },
  { plInputIfaceMgrMsg, "plInputIfaceMgrMsg" },
  { plSceneObject, "plSceneObject" },
  { plAvatarInputStateMsg, "plAvatarInputStateMsg" },
  { plArmatureLODMod, "plArmatureLODMod" },
  { plPythonFileMod, "plPythonFileMod" },
  { plAvBrainGenericMsg, "plAvBrainGenericMsg" },
  { plAvSeekMsg, "plAvSeekMsg" },
  { plServerReplyMsg, "plServerReplyMsg" },
  { plLogicModifier, "plLogicModifier" },
  { plResponderModifier, "plResponderModifier" },
  { plClothingMsg, "plClothingMsg" },
  { plClothingOutfit, "plClothingOutfit" },
  { plAvTaskMsg, "plAvTaskMsg" },
  { plLinkEffectsMgr, "plLinkEffectsMgr" },
  { plLinkEffectsTriggerMsg, "plLinkEffectsTriggerMsg" },
  { plEnableMsg, "plEnableMsg" },
  { plAnimCmdMsg, "plAnimCmdMsg" },
  { plAvAnimTask, "plAvAnimTask" },
  { plMultistageBehMod, "plMultistageBehMod" },
  { plSittingModifier, "plSittingModifier" },
  { pfClimbingWallMsg, "pfClimbingWallMsg" },
  { plClimbEventMsg, "plClimbEventMsg" }, /* also pfClimbingWallMsg2 */
  { plClimbEventMsg2, "plClimbEventMsg2" }, /* also plNetMsgSystemView */
  { plClimbMsg, "plClimbMsg" },
  { plPseudoLinkEffectMsg, "plPseudoLinkEffectMsg" },
  { plPseudoLinkEffectMsg2, "plPseudoLinkEffectMsg2" }, /* also plPseudoLinkAnimTriggerMsg */
  { plWarpMsg, "plWarpMsg" },
  { plSubWorldMsg, "plSubWorldMsg" },
  { plHKSubWorld, "plHKSubWorld" },
  { plHKPhysical, "plHKPhysical" },
  { plSubworldRegionDetector, "plSubworldRegionDetector" },
  { plSimulationMgr, "plSimulationMgr" },
  { plAvTaskBrain, "plAvTaskBrain" },
  { plAvBrainGeneric, "plAvBrainGeneric" },
  { plAvOneShotMsg, "plAvOneShotMsg" },
  { plClient, "plClient" },
  { pfMarkerMgr, "pfMarkerMgr" },
  { plLayerAnimation, "plLayerAnimation" },
  { plATCAnim, "plATCAnim" },
  { plArmatureMod, "plArmatureMod" },
  { plAvLadderMod, "plAvLadderMod" },
  { plClothingItem, "plClothingItem" },
  { plCoopCoordinator, "plCoopCoordinator" },
  { plAvCoopMsg, "plAvCoopMsg" },
  { plAvBrainCoop, "plAvBrainCoop" }, /* also plAvCoopMsg2 */
  { plControlEventMsg, "plControlEventMsg" },
  { plMultistageModMsg, "plMultistageModMsg" },
  { plSharedMesh, "plSharedMesh" },
  { plAnimStage, "plAnimStage" },
  { plAvOneShotLinkTask, "plAvOneShotLinkTask" },
  { plAvOneShotLinkTask2, "plAvOneShotLinkTask2" },
  { plVaultNodeRef, "plVaultNodeRef" },
  { plVaultNode, "plVaultNode or plVaultNodeRef2" },
  { plVaultNode2, "plVaultNode2" }, /* plVaultFolderNode in UU */
  { plNPCSpawnMod, "plNPCSpawnMod" },
  { plSetNetGroupIDMsg, "plSetNetGroupIDMsg" },
  { plSetNetGroupIDMsg2, "plSetNetGroupIDMsg2" }, /* pfBackdoorMsg in UU */
  { plShiftMassMsg, "plShiftMassMsg" },
  { plTorqueMsg, "plTorqueMsg" },
  { plImpulseMsg, "plImpulseMsg" },
  { plOffsetImpulseMsg, "plOffsetImpulseMsg" },
  { plAngularImpulseMsg, "plAngularImpulseMsg" },
  { plForceMsg, "plForceMsg" },
  { plDampMsg, "plDampMsg" },
  { plOffsetForceMsg, "plOffsetForceMsg" }, /* TODO: need specimen */
  { plAvEnableMsg, "plAvEnableMsg" },
  { plCreatableGenericValue, "plCreatableGenericValue" },
  { plCreatableStream, "plCreatableStream" },
  { plServerGuid, "plServerGuid" },
  { plAgeLinkStruct, "plAgeLinkStruct" },
  { plLoadCloneMsg, "plLoadCloneMsg" },
  { plParticleTransferMsg, "plParticleTransferMsg" },
  { plParticleKillMsg, "plParticleKillMsg" },
#ifdef INCLUDE_ALL_TYPES
  /* this is ALL the types, with the ones I've encountered above taken out;
     the reason for this is to help identify things */
  /* note, this duplicates stuff in the plNetMsgs array - consider merging */
  { plSceneNode, "plSceneNode" },
  { hsKeyedObject, "hsKeyedObject" },
  { plBitmap, "plBitmap" },
  { plMipmap, "plMipmap" },
  { plCubicEnvironmap, "plCubicEnvironmap" },
  { plLayer, "plLayer" },
  { hsGMaterial, "hsGMaterial" },
  { plParticleSystem, "plParticleSystem" },
  { plParticleEffect, "plParticleEffect" },
  { plParticleCollisionEffectBeat, "plParticleCollisionEffectBeat" },
  { plParticleFadeVolumeEffect, "plParticleFadeVolumeEffect" },
  { plBoundInterface, "plBoundInterface" },
  { plRenderTarget, "plRenderTarget" },
  { plCubicRenderTarget, "plCubicRenderTarget" },
  { plCubicRenderTargetModifier, "plCubicRenderTargetModifier" },
  { plObjInterface, "plObjInterface" },
  { plAudioInterface, "plAudioInterface" },
  { plAudible, "plAudible" },
  { plAudibleNull, "plAudibleNull" },
  { plWinAudible, "plWinAudible" },
  { plCoordinateInterface, "plCoordinateInterface" },
  { plDrawInterface, "plDrawInterface" },
  { plDrawable, "plDrawable" },
  { plDrawableMesh, "plDrawableMesh" },
  { plDrawableIce, "plDrawableIce" },
  { plPhysical, "plPhysical" },
  { plPhysicalMesh, "plPhysicalMesh" },
  { plSimulationInterface, "plSimulationInterface" },
  { plCameraModifier, "plCameraModifier" },
  { plModifier, "plModifier" },
  { plSingleModifier, "plSingleModifier" },
  { plSimpleModifier, "plSimpleModifier" },
  { plSimpleTMModifier, "plSimpleTMModifier" },
  { plRandomTMModifier, "plRandomTMModifier" },
  { plInterestingModifier, "plInterestingModifier" },
  { plDetectorModifier, "plDetectorModifier" },
  { plSimplePhysicalMesh, "plSimplePhysicalMesh" },
  { plCompoundPhysicalMesh, "plCompoundPhysicalMesh" },
  { plMultiModifier, "plMultiModifier" },
  { plSynchedObject, "plSynchedObject" },
  { plSoundBuffer, "plSoundBuffer" },
  { plAliasModifier, "plAliasModifier" },
  { plPickingDetector, "plPickingDetector" },
  { plCollisionDetector, "plCollisionDetector" },
  { plConditionalObject, "plConditionalObject" },
  { plANDConditionalObject, "plANDConditionalObject" },
  { plORConditionalObject, "plORConditionalObject" },
  { plPickedConditionalObject, "plPickedConditionalObject" },
  { plActivatorConditionalObject, "plActivatorConditionalObject" },
  { plTimerCallbackManager, "plTimerCallbackManager" },
  { plKeyPressConditionalObject, "plKeyPressConditionalObject" },
  { plAnimationEventConditionalObject, "plAnimationEventConditionalObject" },
  { plControlEventConditionalObject, "plControlEventConditionalObject" },
  { plObjectInBoxConditionalObject, "plObjectInBoxConditionalObject" },
  { plLocalPlayerInBoxConditionalObject, "plLocalPlayerInBoxConditionalObject" },
  { plObjectIntersectPlaneConditionalObject, "plObjectIntersectPlaneConditionalObject" },
  { plLocalPlayerIntersectPlaneConditionalObject, "plLocalPlayerIntersectPlaneConditionalObject" },
  { plPortalDrawable, "plPortalDrawable" },
  { plPortalPhysical, "plPortalPhysical" },
  { plSpawnModifier, "plSpawnModifier" },
  { plFacingConditionalObject, "plFacingConditionalObject" },
  { plViewFaceModifier, "plViewFaceModifier" },
  { plLayerInterface, "plLayerInterface" },
  { plLayerWrapper, "plLayerWrapper" },
  { plLayerDepth, "plLayerDepth" },
  { plLayerMovie, "plLayerMovie" },
  { plLayerBink, "plLayerBink" },
  { plLayerAVI, "plLayerAVI" },
  { plSound, "plSound" },
  { plWin32Sound, "plWin32Sound" },
  { plLayerOr, "plLayerOr" },
  { plAudioSystem, "plAudioSystem" },
  { plDrawableSpans, "plDrawableSpans" },
  { plDrawablePatchSet, "plDrawablePatchSet" },
  { plInputManager, "plInputManager" },
  { plLogicModBase, "plLogicModBase" },
  { plFogEnvironment, "plFogEnvironment" },
  { plNetApp, "plNetApp" },
  { pl2WayWinAudible, "pl2WayWinAudible" },
  { plLightInfo, "plLightInfo" },
  { plDirectionalLightInfo, "plDirectionalLightInfo" },
  { plOmniLightInfo, "plOmniLightInfo" },
  { plSpotLightInfo, "plSpotLightInfo" },
  { plLightSpace, "plLightSpace" },
  { plNetClientApp, "plNetClientApp" },
  { plNetServerApp, "plNetServerApp" },
  { plCompoundTMModifier, "plCompoundTMModifier" },
  { plCameraBrain, "plCameraBrain" },
  { plCameraBrain_Default, "plCameraBrain_Default" },
  { plCameraBrain_Drive, "plCameraBrain_Drive" },
  { plCameraBrain_Fixed, "plCameraBrain_Fixed" },
  { plCameraBrain_FixedPan, "plCameraBrain_FixedPan" },
  { pfGUIClickMapCtrl, "pfGUIClickMapCtrl" },
  { plListener, "plListener" },
  { plAvatarMod, "plAvatarMod" },
  { plAvatarAnim, "plAvatarAnim" },
  { plAvatarAnimMgr, "plAvatarAnimMgr" },
  { plOccluder, "plOccluder" },
  { plMobileOccluder, "plMobileOccluder" },
  { plLayerShadowBase, "plLayerShadowBase" },
  { plLimitedDirLightInfo, "plLimitedDirLightInfo" },
  { plAGAnim, "plAGAnim" },
  { plAGModifier, "plAGModifier" },
  { plAGMasterMod, "plAGMasterMod" },
  { plCameraBrain_Avatar, "plCameraBrain_Avatar" },
  { plCameraRegionDetector, "plCameraRegionDetector" },
  { plCameraBrain_FP, "plCameraBrain_FP" },
  { plLineFollowMod, "plLineFollowMod" },
  { plLightModifier, "plLightModifier" },
  { plOmniModifier, "plOmniModifier" },
  { plSpotModifier, "plSpotModifier" },
  { plLtdDirModifier, "plLtdDirModifier" },
  { plSeekPointMod, "plSeekPointMod" },
  { plOneShotMod, "plOneShotMod" },
  { plRandomCommandMod, "plRandomCommandMod" },
  { plRandomSoundMod, "plRandomSoundMod" },
  { plPostEffectMod, "plPostEffectMod" },
  { plObjectInVolumeDetector, "plObjectInVolumeDetector" },
  { plAxisAnimModifier, "plAxisAnimModifier" },
  { plLayerLightBase, "plLayerLightBase" },
  { plFollowMod, "plFollowMod" },
  { plTransitionMgr, "plTransitionMgr" },
  { plInventoryMod, "plInventoryMod" },
  { plInventoryObjMod, "plInventoryObjMod" },
  { plWin32StreamingSound, "plWin32StreamingSound" },
  { plPythonMod, "plPythonMod" },
  { plActivatorActivatorConditionalObject, "plActivatorActivatorConditionalObject" },
  { plSoftVolume, "plSoftVolume" },
  { plSoftVolumeSimple, "plSoftVolumeSimple" },
  { plSoftVolumeComplex, "plSoftVolumeComplex" },
  { plSoftVolumeUnion, "plSoftVolumeUnion" },
  { plSoftVolumeIntersect, "plSoftVolumeIntersect" },
  { plSoftVolumeInvert, "plSoftVolumeInvert" },
  { plWin32LinkSound, "plWin32LinkSound" },
  { plLayerLinkAnimation, "plLayerLinkAnimation" },
  { plCameraBrain_Freelook, "plCameraBrain_Freelook" },
  { plHavokConstraintsMod, "plHavokConstraintsMod" },
  { plHingeConstraintMod, "plHingeConstraintMod" },
  { plWheelConstraintMod, "plWheelConstraintMod" },
  { plStrongSpringConstraintMod, "plStrongSpringConstraintMod" },
  { plWin32StaticSound, "plWin32StaticSound" },
  { pfGameGUIMgr, "pfGameGUIMgr" },
  { pfGUIDialogMod, "pfGUIDialogMod" },
  { plCameraBrain1, "plCameraBrain1" },
  { plVirtualCam1, "plVirtualCam1" },
  { plCameraModifier1, "plCameraModifier1" },
  { plCameraBrain1_Drive, "plCameraBrain1_Drive" },
  { plCameraBrain1_POA, "plCameraBrain1_POA" },
  { plCameraBrain1_Avatar, "plCameraBrain1_Avatar" },
  { plCameraBrain1_Fixed, "plCameraBrain1_Fixed" },
  { plCameraBrain1_POAFixed, "plCameraBrain1_POAFixed" },
  { pfGUIButtonMod, "pfGUIButtonMod" },
  { pfGUIControlMod, "pfGUIControlMod" },
  { plExcludeRegionModifier, "plExcludeRegionModifier" },
  { pfGUIDraggableMod, "pfGUIDraggableMod" },
  { plVolumeSensorConditionalObject, "plVolumeSensorConditionalObject" },
  { plVolActivatorConditionalObject, "plVolActivatorConditionalObject" },
  { plMsgForwarder, "plMsgForwarder" },
  { plBlower, "plBlower" },
  { pfGUIListBoxMod, "pfGUIListBoxMod" },
  { pfGUITextBoxMod, "pfGUITextBoxMod" },
  { pfGUIEditBoxMod, "pfGUIEditBoxMod" },
  { plDynamicTextMap, "plDynamicTextMap" },
  { pfGUIUpDownPairMod, "pfGUIUpDownPairMod" },
  { pfGUIValueCtrl, "pfGUIValueCtrl" },
  { pfGUIKnobCtrl, "pfGUIKnobCtrl" },
  { plCameraBrain1_FirstPerson, "plCameraBrain1_FirstPerson" },
  { plCloneSpawnModifier, "plCloneSpawnModifier" },
  { plClothingBase, "plClothingBase" },
  { plClothingMgr, "plClothingMgr" },
  { pfGUIDragBarCtrl, "pfGUIDragBarCtrl" },
  { pfGUICheckBoxCtrl, "pfGUICheckBoxCtrl" },
  { pfGUIRadioGroupCtrl, "pfGUIRadioGroupCtrl" },
  { pfPlayerBookMod, "pfPlayerBookMod" },
  { pfGUIDynDisplayCtrl, "pfGUIDynDisplayCtrl" },
  { plLayerProject, "plLayerProject" },
  { plInputInterfaceMgr, "plInputInterfaceMgr" },
  { plRailCameraMod, "plRailCameraMod" },
  { plCameraBrain1_Circle, "plCameraBrain1_Circle" },
  { plParticleWindEffect, "plParticleWindEffect" },
  { plAnimEventModifier, "plAnimEventModifier" },
  { plAutoProfile, "plAutoProfile" },
  { pfGUISkin, "pfGUISkin" },
  { plAVIWriter, "plAVIWriter" },
  { plParticleCollisionEffect, "plParticleCollisionEffect" },
  { plParticleCollisionEffectDie, "plParticleCollisionEffectDie" },
  { plParticleCollisionEffectBounce, "plParticleCollisionEffectBounce" },
  { plInterfaceInfoModifier, "plInterfaceInfoModifier" },
  { plArmatureEffectsMgr, "plArmatureEffectsMgr" },
  { plVehicleModifier, "plVehicleModifier" },
  { plParticleLocalWind, "plParticleLocalWind" },
  { plParticleUniformWind, "plParticleUniformWind" },
  { plInstanceDrawInterface, "plInstanceDrawInterface" },
  { plShadowMaster, "plShadowMaster" },
  { plShadowCaster, "plShadowCaster" },
  { plPointShadowMaster, "plPointShadowMaster" },
  { plDirectShadowMaster, "plDirectShadowMaster" },
  { plSDLModifier, "plSDLModifier" },
  { plPhysicalSDLModifier, "plPhysicalSDLModifier" },
  { plClothingSDLModifier, "plClothingSDLModifier" },
  { plAvatarSDLModifier, "plAvatarSDLModifier" },
  { plAGMasterSDLModifier, "plAGMasterSDLModifier" },
  { plPythonSDLModifier, "plPythonSDLModifier" },
  { plLayerSDLModifier, "plLayerSDLModifier" },
  { plAnimTimeConvertSDLModifier, "plAnimTimeConvertSDLModifier" },
  { plResponderSDLModifier, "plResponderSDLModifier" },
  { plSoundSDLModifier, "plSoundSDLModifier" },
  { plResManagerHelper, "plResManagerHelper" },
  { plArmatureEffect, "plArmatureEffect" },
  { plArmatureEffectFootSound, "plArmatureEffectFootSound" },
  { plEAXListenerMod, "plEAXListenerMod" },
  { plDynaDecalMgr, "plDynaDecalMgr" },
  { plObjectInVolumeAndFacingDetector, "plObjectInVolumeAndFacingDetector" },
  { plDynaFootMgr, "plDynaFootMgr" },
  { plDynaRippleMgr, "plDynaRippleMgr" },
  { plDynaBulletMgr, "plDynaBulletMgr" },
  { plDecalEnableMod, "plDecalEnableMod" },
  { plPrintShape, "plPrintShape" },
  { plDynaPuddleMgr, "plDynaPuddleMgr" },
  { pfGUIMultiLineEditCtrl, "pfGUIMultiLineEditCtrl" },
  { plLayerAnimationBase, "plLayerAnimationBase" },
  { plLayerSDLAnimation, "plLayerSDLAnimation" },
  { plAgeGlobalAnim, "plAgeGlobalAnim" },
  { plActivePrintShape, "plActivePrintShape" },
  { plExcludeRegionSDLModifier, "plExcludeRegionSDLModifier" },
  { plLOSDispatch, "plLOSDispatch" },
  { plDynaWakeMgr, "plDynaWakeMgr" },
  { plWaveSet7, "plWaveSet7" },
  { plPanicLinkRegion, "plPanicLinkRegion" },
  { plWin32GroupedSound, "plWin32GroupedSound" },
  { plFilterCoordInterface, "plFilterCoordInterface" },
  { plStereizer, "plStereizer" },
  { plCCRMgr, "plCCRMgr" },
  { plCCRSpecialist, "plCCRSpecialist" },
  { plCCRSeniorSpecialist, "plCCRSeniorSpecialist" },
  { plCCRShiftSupervisor, "plCCRShiftSupervisor" },
  { plCCRGameOperator, "plCCRGameOperator" },
  { plShader, "plShader" },
  { plDynamicEnvMap, "plDynamicEnvMap" },
  { plSimpleRegionSensor, "plSimpleRegionSensor" },
  { plMorphSequence, "plMorphSequence" },
  { plEmoteAnim, "plEmoteAnim" },
  { plDynaRippleVSMgr, "plDynaRippleVSMgr" },
  { plWaveSet6, "plWaveSet6" },
  { pfGUIProgressCtrl, "pfGUIProgressCtrl" },
  { plMaintainersMarkerModifier, "plMaintainersMarkerModifier" },
  { plMorphSequenceSDLMod, "plMorphSequenceSDLMod" },
  { plMorphDataSet, "plMorphDataSet" },
  { plHardRegion, "plHardRegion" },
  { plHardRegionPlanes, "plHardRegionPlanes" },
  { plHardRegionComplex, "plHardRegionComplex" },
  { plHardRegionUnion, "plHardRegionUnion" },
  { plHardRegionIntersect, "plHardRegionIntersect" },
  { plHardRegionInvert, "plHardRegionInvert" },
  { plVisRegion, "plVisRegion" },
  { plVisMgr, "plVisMgr" },
  { plRegionBase, "plRegionBase" },
  { pfGUIPopUpMenu, "pfGUIPopUpMenu" },
  { pfGUIMenuItem, "pfGUIMenuItem" },
  { plFont, "plFont" },
  { plFontCache, "plFontCache" },
  { plRelevanceRegion, "plRelevanceRegion" },
  { plRelevanceMgr, "plRelevanceMgr" },
  { pfJournalBook, "pfJournalBook" },
  { plLayerTargetContainer, "plLayerTargetContainer" },
  { plImageLibMod, "plImageLibMod" },
  { plParticleFlockEffect, "plParticleFlockEffect" },
  { plParticleSDLMod, "plParticleSDLMod" },
  { plAgeLoader, "plAgeLoader" },
  { plWaveSetBase, "plWaveSetBase" },
  { plPhysicalSndGroup, "plPhysicalSndGroup" },
  { pfBookData, "pfBookData" },
  { plDynaTorpedoMgr, "plDynaTorpedoMgr" },
  { plDynaTorpedoVSMgr, "plDynaTorpedoVSMgr" },
  { plClusterGroup, "plClusterGroup" },
  { plGameMarkerModifier, "plGameMarkerModifier" },
  { plLODMipmap, "plLODMipmap" },
  { plSwimDetector, "plSwimDetector" }, /* plSwimRegion in UU */
  { plFadeOpacityMod, "plFadeOpacityMod" },
  { plFadeOpacityLay, "plFadeOpacityLay" },
  { plDistOpacityMod, "plDistOpacityMod" },
  { plArmatureModBase, "plArmatureModBase" },
  { plSwimRegionInterface, "plSwimRegionInterface" },
  { plSwimCircularCurrentRegion, "plSwimCircularCurrentRegion" },
  { plParticleFollowSystemEffect, "plParticleFollowSystemEffect" },
  { plSwimStraightCurrentRegion, "plSwimStraightCurrentRegion" },
  { plObjRefMsg, "plObjRefMsg" },
  { plNodeRefMsg, "plNodeRefMsg" },
  { plMessage, "plMessage" },
  { plRefMsg, "plRefMsg" },
  { plGenRefMsg, "plGenRefMsg" },
  { plTimeMsg, "plTimeMsg" },
  { plParticleUpdateMsg, "plParticleUpdateMsg" },
  { plLayRefMsg, "plLayRefMsg" },
  { plMatRefMsg, "plMatRefMsg" },
  { plCameraMsg, "plCameraMsg" },
  { plInputEventMsg, "plInputEventMsg" },
  { plKeyEventMsg, "plKeyEventMsg" },
  { plMouseEventMsg, "plMouseEventMsg" },
  { plEvalMsg, "plEvalMsg" },
  { plTransformMsg, "plTransformMsg" },
  { plVaultCCRNode, "plVaultCCRNode" },
  { plLOSRequestMsg, "plLOSRequestMsg" },
  { plLOSHitMsg, "plLOSHitMsg" },
  { plSingleModMsg, "plSingleModMsg" },
  { plMultiModMsg, "plMultiModMsg" },
  { plPlayerMsg, "plPlayerMsg" },/* plAvatarPhysicsEnableCallbackMsg in PotS */
  { plMemberUpdateMsg, "plMemberUpdateMsg" },
  { plNetMsgPagingRoom, "plNetMsgPagingRoom" },
  { plActivatorMsg, "plActivatorMsg" },
  { plDispatch, "plDispatch" },
  { plReceiver, "plReceiver" },
  { plMeshRefMsg, "plMeshRefMsg" },
  { hsGRenderProcs, "hsGRenderProcs" },
  { hsSfxAngleFade, "hsSfxAngleFade" },
  { hsSfxDistFade, "hsSfxDistFade" },
  { hsSfxDistShade, "hsSfxDistShade" },
  { hsSfxGlobalShade, "hsSfxGlobalShade" },
  { hsSfxIntenseAlpha, "hsSfxIntenseAlpha" },
  { hsSfxObjDistFade, "hsSfxObjDistFade" },
  { hsSfxObjDistShade, "hsSfxObjDistShade" },
  { hsDynamicValue, "hsDynamicValue" },
  { hsDynamicScalar, "hsDynamicScalar" },
  { hsDynamicColorRGBA, "hsDynamicColorRGBA" },
  { hsDynamicMatrix33, "hsDynamicMatrix33" },
  { hsDynamicMatrix44, "hsDynamicMatrix44" },
  { plController, "plController" },
  { plLeafController, "plLeafController" },
  { plScaleController, "plScaleController" },
  { plRotController, "plRotController" },
  { plPosController, "plPosController" },
  { plScalarController, "plScalarController" },
  { plPoint3Controller, "plPoint3Controller" },
  { plScaleValueController, "plScaleValueController" },
  { plQuatController, "plQuatController" },
  { plMatrix33Controller, "plMatrix33Controller" },
  { plMatrix44Controller, "plMatrix44Controller" },
  { plEaseController, "plEaseController" },
  { plSimpleScaleController, "plSimpleScaleController" },
  { plSimpleRotController, "plSimpleRotController" },
  { plCompoundRotController, "plCompoundRotController" },
  { plSimplePosController, "plSimplePosController" },
  { plCompoundPosController, "plCompoundPosController" },
  { plTMController, "plTMController" },
  { hsFogControl, "hsFogControl" },
  { plIntRefMsg, "plIntRefMsg" },
  { plCollisionReactor, "plCollisionReactor" },
  { plCorrectionMsg, "plCorrectionMsg" },
  { plPhysicalModifier, "plPhysicalModifier" },
  { plPickedMsg, "plPickedMsg" },
  { plCollideMsg, "plCollideMsg" },
  { plTriggerMsg, "plTriggerMsg" },
  { plInterestingModMsg, "plInterestingModMsg" },
  { plDebugKeyEventMsg, "plDebugKeyEventMsg" },
  { plPhysicalProperties, "plPhysicalProperties" },
  { plSimplePhys, "plSimplePhys" },
  { plMatrixUpdateMsg, "plMatrixUpdateMsg" },
  { plCondRefMsg, "plCondRefMsg" },
  { plTimerCallbackMsg, "plTimerCallbackMsg" },
  { plEventCallbackMsg, "plEventCallbackMsg" },
  { plSpawnModMsg, "plSpawnModMsg" },
  { plSpawnRequestMsg, "plSpawnRequestMsg" },
  { plAttachMsg, "plAttachMsg" },
  { pfConsole, "pfConsole" },
  { plRenderMsg, "plRenderMsg" },
  { plAnimTimeConvert, "plAnimTimeConvert" },
  { plSoundMsg, "plSoundMsg" },
  { plInterestingPing, "plInterestingPing" },
  { plNodeCleanupMsg, "plNodeCleanupMsg" },
  { plSpaceTree, "plSpaceTree" },
  { plNetMessage, "plNetMessage" },
  { plNetMsgJoinReq, "plNetMsgJoinReq" },
  { plNetMsgJoinAck, "plNetMsgJoinAck" },
  { plNetMsgLeave, "plNetMsgLeave" },
  { plNetMsgPing, "plNetMsgPing" },
  { plNetMsgRoomsList, "plNetMsgRoomsList" },
  { plNetMsgGroupOwner, "plNetMsgGroupOwner" },
  { plNetMsgGameStateRequest, "plNetMsgGameStateRequest" },
  { plNetMsgSessionReset, "plNetMsgSessionReset" },
  { plNetMsgOmnibus, "plNetMsgOmnibus" },
  { plNetMsgObject, "plNetMsgObject" },
  { plCCRInvisibleMsg, "plCCRInvisibleMsg" },
  { plLinkInDoneMsg, "plLinkInDoneMsg" },
  { plNetMsgGameMessage, "plNetMsgGameMessage" },
  { plNetMsgStream, "plNetMsgStream" },
  { plAudioSysMsg, "plAudioSysMsg" },
  { plDispatchBase, "plDispatchBase" },
  { plDeviceRecreateMsg, "plDeviceRecreateMsg" },
  { plNetMsgStreamHelper, "plNetMsgStreamHelper" },
  { plNetMsgObjectHelper, "plNetMsgObjectHelper" },
  { plIMouseXEventMsg, "plIMouseXEventMsg" },
  { plIMouseYEventMsg, "plIMouseYEventMsg" },
  { plIMouseBEventMsg, "plIMouseBEventMsg" },
  { plLogicTriggerMsg, "plLogicTriggerMsg" },
  { plPipeline, "plPipeline" },
  { plDX8Pipeline, "plDX8Pipeline" },
  { plNetMsgVoice, "plNetMsgVoice" },
  { plLightRefMsg, "plLightRefMsg" },
  { plNetMsgStreamedObject, "plNetMsgStreamedObject" },
  { plNetMsgSharedState, "plNetMsgSharedState" },
  { plNetMsgTestAndSet, "plNetMsgTestAndSet" },
  { plNetMsgGetSharedState, "plNetMsgGetSharedState" },
  { plSharedStateMsg, "plSharedStateMsg" },
  { plNetGenericServerTask, "plNetGenericServerTask" },
  { plNetLookupServerGetAgeInfoFromVaultTask, "plNetLookupServerGetAgeInfoFromVaultTask" },
  { plLoadAgeMsg, "plLoadAgeMsg" },
  { plMessageWithCallbacks, "plMessageWithCallbacks" },
  { plClientMsg, "plClientMsg" },
  { plClientRefMsg, "plClientRefMsg" },
  { plNetMsgObjStateRequest, "plNetMsgObjStateRequest" },
  { plCCRPetitionMsg, "plCCRPetitionMsg" },
  { plVaultCCRInitializationTask, "plVaultCCRInitializationTask" },
  { plNetServerMsg, "plNetServerMsg" },
  { plNetServerMsgWithContext, "plNetServerMsgWithContext" },
  { plNetServerMsgRegisterServer, "plNetServerMsgRegisterServer" },
  { plNetServerMsgUnregisterServer, "plNetServerMsgUnregisterServer" },
  { plNetServerMsgStartProcess, "plNetServerMsgStartProcess" },
  { plNetServerMsgRegisterProcess, "plNetServerMsgRegisterProcess" },
  { plNetServerMsgUnregisterProcess, "plNetServerMsgUnregisterProcess" },
  { plNetServerMsgFindProcess, "plNetServerMsgFindProcess" },
  { plNetServerMsgProcessFound, "plNetServerMsgProcessFound" },
  { plNetMsgRoutingInfo, "plNetMsgRoutingInfo" },
  { plNetServerSessionInfo, "plNetServerSessionInfo" },
  { plSimulationMsg, "plSimulationMsg" },
  { plSimulationSynchMsg, "plSimulationSynchMsg" },
  { plHKSimulationSynchMsg, "plHKSimulationSynchMsg" },
  { plAvatarMsg, "plAvatarMsg" },
  { plSatisfiedMsg, "plSatisfiedMsg" },
  { plNetMsgObjectListHelper, "plNetMsgObjectListHelper" },
  { plNetMsgObjectUpdateFilter, "plNetMsgObjectUpdateFilter" },
  { plProxyDrawMsg, "plProxyDrawMsg" },
  { plSelfDestructMsg, "plSelfDestructMsg" },
  { plSimInfluenceMsg, "plSimInfluenceMsg" },
  { plSimStateMsg, "plSimStateMsg" },
  { plFreezeMsg, "plFreezeMsg" },
  { plEventGroupMsg, "plEventGroupMsg" },
  { plSuspendEventMsg, "plSuspendEventMsg" },
  { plNetMsgMembersListReq, "plNetMsgMembersListReq" },
  { plNetMsgMembersList, "plNetMsgMembersList" },
  { plNetMsgMemberInfoHelper, "plNetMsgMemberInfoHelper" },
  { plNetMsgMemberListHelper, "plNetMsgMemberListHelper" },
  { plNetMsgMemberUpdate, "plNetMsgMemberUpdate" },
  { plNetMsgServerToClient, "plNetMsgServerToClient" },
  { plNetMsgCreatePlayer, "plNetMsgCreatePlayer" },
  { plNetMsgAuthenticateHello, "plNetMsgAuthenticateHello" },
  { plNetMsgAuthenticateChallenge, "plNetMsgAuthenticateChallenge" },
  { plConnectedToVaultMsg, "plConnectedToVaultMsg" },
  { plCCRCommunicationMsg, "plCCRCommunicationMsg" },
  { plNetMsgInitialAgeStateSent, "plNetMsgInitialAgeStateSent" },
  { plInitialAgeStateLoadedMsg, "plInitialAgeStateLoadedMsg" },
  { plNetServerMsgFindServerBase, "plNetServerMsgFindServerBase" },
  { plNetServerMsgFindServerReplyBase, "plNetServerMsgFindServerReplyBase" },
  { plNetServerMsgFindAuthServer, "plNetServerMsgFindAuthServer" },
  { plNetServerMsgFindAuthServerReply, "plNetServerMsgFindAuthServerReply" },
  { plNetServerMsgFindVaultServer, "plNetServerMsgFindVaultServer" },
  { plNetServerMsgFindVaultServerReply, "plNetServerMsgFindVaultServerReply" },
  { plAvTaskSeekDoneMsg, "plAvTaskSeekDoneMsg" },
  { UNUSED____plNetServerMsgFindAdminServerReply, "UNUSED____plNetServerMsgFindAdminServerReply" },
  { plNetServerMsgVaultTask, "plNetServerMsgVaultTask" },
  { plNetMsgVaultTask, "plNetMsgVaultTask" },
  { plVaultAgeInfoNode, "plVaultAgeInfoNode" },
  { plNetMsgStreamableHelper, "plNetMsgStreamableHelper" },
  { plNetMsgReceiversListHelper, "plNetMsgReceiversListHelper" },
  { plNetMsgListenListUpdate, "plNetMsgListenListUpdate" },
  { plNetServerMsgPing, "plNetServerMsgPing" },
  { plNetMsgAlive, "plNetMsgAlive" },
  { plNetMsgTerminated, "plNetMsgTerminated" },
  { plSDLModifierMsg, "plSDLModifierMsg" },
  { plNetMsgSDLState, "plNetMsgSDLState" },
  { plNetServerMsgSessionReset, "plNetServerMsgSessionReset" },
  { plCCRBanLinkingMsg, "plCCRBanLinkingMsg" },
  { plCCRSilencePlayerMsg, "plCCRSilencePlayerMsg" },
  { plRenderRequestMsg, "plRenderRequestMsg" },
  { plRenderRequestAck, "plRenderRequestAck" },
  { plNetMember, "plNetMember" },
  { plNetGameMember, "plNetGameMember" },
  { plNetTransportMember, "plNetTransportMember" },
  { plConvexVolume, "plConvexVolume" },
  { plParticleGenerator, "plParticleGenerator" },
  { plSimpleParticleGenerator, "plSimpleParticleGenerator" },
  { plParticleEmitter, "plParticleEmitter" },
  { plAGChannel, "plAGChannel" },
  { plMatrixChannel, "plMatrixChannel" },
  { plMatrixTimeScale, "plMatrixTimeScale" },
  { plMatrixBlend, "plMatrixBlend" },
  { plMatrixControllerChannel, "plMatrixControllerChannel" },
  { plQuatPointCombine, "plQuatPointCombine" },
  { plPointChannel, "plPointChannel" },
  { plPointConstant, "plPointConstant" },
  { plPointBlend, "plPointBlend" },
  { plQuatChannel, "plQuatChannel" },
  { plQuatConstant, "plQuatConstant" },
  { plQuatBlend, "plQuatBlend" },
  { plPlayerPageMsg, "plPlayerPageMsg" },
  { plCmdIfaceModMsg, "plCmdIfaceModMsg" },
  { plNetServerMsgPlsUpdatePlayer, "plNetServerMsgPlsUpdatePlayer" },
  { plListenerMsg, "plListenerMsg" },
  { plAnimPath, "plAnimPath" },
  { plClothingUpdateBCMsg, "plClothingUpdateBCMsg" },
  { plFakeOutMsg, "plFakeOutMsg" },
  { plCursorChangeMsg, "plCursorChangeMsg" },
  { plNodeChangeMsg, "plNodeChangeMsg" },
  { plLinkCallbackMsg, "plLinkCallbackMsg" },
  { plTransitionMsg, "plTransitionMsg" },
  { plConsoleMsg, "plConsoleMsg" },
  { plVolumeIsect, "plVolumeIsect" },
  { plSphereIsect, "plSphereIsect" },
  { plConeIsect, "plConeIsect" },
  { plCylinderIsect, "plCylinderIsect" },
  { plParallelIsect, "plParallelIsect" },
  { plConvexIsect, "plConvexIsect" },
  { plComplexIsect, "plComplexIsect" },
  { plUnionIsect, "plUnionIsect" },
  { plIntersectionIsect, "plIntersectionIsect" },
  { plModulator, "plModulator" },
  { plInventoryMsg, "plInventoryMsg" },
  { plLinkEffectBCMsg, "plLinkEffectBCMsg" },
  { plResponderEnableMsg, "plResponderEnableMsg" },
  { plNetServerMsgHello, "plNetServerMsgHello" },
  { plNetServerMsgHelloReply, "plNetServerMsgHelloReply" },
  { plNetServerMember, "plNetServerMember" },
  { plResponderMsg, "plResponderMsg" },
  { plOneShotMsg, "plOneShotMsg" },
  { plVaultAgeInfoListNode, "plVaultAgeInfoListNode" },
  { plNetServerMsgServerRegistered, "plNetServerMsgServerRegistered" },
  { plPointTimeScale, "plPointTimeScale" },
  { plPointControllerChannel, "plPointControllerChannel" },
  { plQuatTimeScale, "plQuatTimeScale" },
  { plAGApplicator, "plAGApplicator" },
  { plMatrixChannelApplicator, "plMatrixChannelApplicator" },
  { plPointChannelApplicator, "plPointChannelApplicator" },
  { plLightDiffuseApplicator, "plLightDiffuseApplicator" },
  { plLightAmbientApplicator, "plLightAmbientApplicator" },
  { plLightSpecularApplicator, "plLightSpecularApplicator" },
  { plOmniApplicator, "plOmniApplicator" },
  { plQuatChannelApplicator, "plQuatChannelApplicator" },
  { plScalarChannel, "plScalarChannel" },
  { plScalarTimeScale, "plScalarTimeScale" },
  { plScalarBlend, "plScalarBlend" },
  { plScalarControllerChannel, "plScalarControllerChannel" },
  { plScalarChannelApplicator, "plScalarChannelApplicator" },
  { plSpotInnerApplicator, "plSpotInnerApplicator" },
  { plSpotOuterApplicator, "plSpotOuterApplicator" },
  { plNetServerMsgPlsRoutableMsg, "plNetServerMsgPlsRoutableMsg" },
  { plPuppetBrainMsg, "plPuppetBrainMsg" },
  { plATCEaseCurve, "plATCEaseCurve" },
  { plConstAccelEaseCurve, "plConstAccelEaseCurve" },
  { plSplineEaseCurve, "plSplineEaseCurve" },
  { plVaultAgeInfoInitializationTask, "plVaultAgeInfoInitializationTask" },
  { pfGameGUIMsg, "pfGameGUIMsg" },
  { plNetServerMsgVaultRequestGameState, "plNetServerMsgVaultRequestGameState" },
  { plNetServerMsgVaultGameState, "plNetServerMsgVaultGameState" },
  { plNetServerMsgVaultGameStateSave, "plNetServerMsgVaultGameStateSave" },
  { plNetServerMsgVaultGameStateSaved, "plNetServerMsgVaultGameStateSaved" },
  { plNetServerMsgVaultGameStateLoad, "plNetServerMsgVaultGameStateLoad" },
  { plNetClientTask, "plNetClientTask" },
  { plNetMsgSDLStateBCast, "plNetMsgSDLStateBCast" },
  { plReplaceGeometryMsg, "plReplaceGeometryMsg" },
  { plNetServerMsgExitProcess, "plNetServerMsgExitProcess" },
  { plNetServerMsgSaveGameState, "plNetServerMsgSaveGameState" },
  { plDniCoordinateInfo, "plDniCoordinateInfo" },
  { plNetMsgGameMessageDirected, "plNetMsgGameMessageDirected" },
  { plLinkOutUnloadMsg, "plLinkOutUnloadMsg" },
  { plScalarConstant, "plScalarConstant" },
  { plMatrixConstant, "plMatrixConstant" },
  { plAGCmdMsg, "plAGCmdMsg" },
  { plExcludeRegionMsg, "plExcludeRegionMsg" },
  { plOneTimeParticleGenerator, "plOneTimeParticleGenerator" },
  { plParticleApplicator, "plParticleApplicator" },
  { plParticleLifeMinApplicator, "plParticleLifeMinApplicator" },
  { plParticleLifeMaxApplicator, "plParticleLifeMaxApplicator" },
  { plParticlePPSApplicator, "plParticlePPSApplicator" },
  { plParticleAngleApplicator, "plParticleAngleApplicator" },
  { plParticleVelMinApplicator, "plParticleVelMinApplicator" },
  { plParticleVelMaxApplicator, "plParticleVelMaxApplicator" },
  { plParticleScaleMinApplicator, "plParticleScaleMinApplicator" },
  { plParticleScaleMaxApplicator, "plParticleScaleMaxApplicator" },
  { plDynamicTextMsg, "plDynamicTextMsg" },
  { plCameraTargetFadeMsg, "plCameraTargetFadeMsg" },
  { plAgeLoadedMsg, "plAgeLoadedMsg" },
  { plPointControllerCacheChannel, "plPointControllerCacheChannel" },
  { plScalarControllerCacheChannel, "plScalarControllerCacheChannel" },
  { plLinkEffectsTriggerPrepMsg, "plLinkEffectsTriggerPrepMsg" },
  { plLinkEffectPrepBCMsg, "plLinkEffectPrepBCMsg" },
  { plAgeInfoStruct, "plAgeInfoStruct" },
  { plSDLNotificationMsg, "plSDLNotificationMsg" },
  { plNetClientConnectAgeVaultTask, "plNetClientConnectAgeVaultTask" },
  { plVaultNotifyMsg, "plVaultNotifyMsg" },
  { plPlayerInfo, "plPlayerInfo" },
  { plSwapSpansRefMsg, "plSwapSpansRefMsg" },
  { pfKI, "pfKI" },
  { plDISpansMsg, "plDISpansMsg" },
  { plNetMsgCreatableHelper, "plNetMsgCreatableHelper" },
  { plNetMsgRequestMyVaultPlayerList, "plNetMsgRequestMyVaultPlayerList" },
  { plDelayedTransformMsg, "plDelayedTransformMsg" },
  { plSuperVNodeMgrInitTask, "plSuperVNodeMgrInitTask" },
  { plElementRefMsg, "plElementRefMsg" },
  { plEventGroupEnableMsg, "plEventGroupEnableMsg" },
  { pfGUINotifyMsg, "pfGUINotifyMsg" },
  { plAvBrain, "plAvBrain" },
  { plAvBrainUser, "plAvBrainUser" }, /* plArmatureBrain in PotS */
  { plAvBrainHuman, "plAvBrainHuman" },
  { plAvBrainCritter, "plAvBrainCritter" },
  { plAvBrainDrive, "plAvBrainDrive" },
  { plAvBrainSample, "plAvBrainSample" },
  { plAvBrainPuppet, "plAvBrainPuppet" },
  { plAvBrainLadder, "plAvBrainLadder" },
  { plRemoteAvatarInfoMsg, "plRemoteAvatarInfoMsg" },
  { plMatrixDelayedCorrectionApplicator, "plMatrixDelayedCorrectionApplicator" },
  { plAvPushBrainMsg, "plAvPushBrainMsg" },
  { plAvPopBrainMsg, "plAvPopBrainMsg" },
  { plRoomLoadNotifyMsg, "plRoomLoadNotifyMsg" },
  { plAvTask, "plAvTask" },
  { plAvSeekTask, "plAvSeekTask" },
  { UNUSED_plAvBlendedSeekTask, "UNUSED_plAvBlendedSeekTask" },
  { plAvOneShotTask, "plAvOneShotTask" },
  { plAvEnableTask, "plAvEnableTask" },
  { plNetClientMember, "plNetClientMember" },
  { plNetClientCommTask, "plNetClientCommTask" },
  { plNetServerMsgAuthRequest, "plNetServerMsgAuthRequest" },
  { plNetServerMsgAuthReply, "plNetServerMsgAuthReply" },
  { plNetClientCommAuthTask, "plNetClientCommAuthTask" },
  { plClientGuid, "plClientGuid" },
  { plNetMsgVaultPlayerList, "plNetMsgVaultPlayerList" },
  { plNetMsgSetMyActivePlayer, "plNetMsgSetMyActivePlayer" },
  { plNetServerMsgRequestAccountPlayerList, "plNetServerMsgRequestAccountPlayerList" },
  { plNetServerMsgAccountPlayerList, "plNetServerMsgAccountPlayerList" },
  { plNetMsgPlayerCreated, "plNetMsgPlayerCreated" },
  { plNetServerMsgVaultCreatePlayer, "plNetServerMsgVaultCreatePlayer" },
  { plNetServerMsgVaultPlayerCreated, "plNetServerMsgVaultPlayerCreated" },
  { plNetMsgFindAge, "plNetMsgFindAge" },
  { plNetMsgFindAgeReply, "plNetMsgFindAgeReply" },
  { plNetClientConnectPrepTask, "plNetClientConnectPrepTask" },
  { plNetClientAuthTask, "plNetClientAuthTask" },
  { plNetClientGetPlayerVaultTask, "plNetClientGetPlayerVaultTask" },
  { plNetClientSetActivePlayerTask, "plNetClientSetActivePlayerTask" },
  { plNetClientFindAgeTask, "plNetClientFindAgeTask" },
  { plNetClientLeaveTask, "plNetClientLeaveTask" },
  { plNetClientJoinTask, "plNetClientJoinTask" },
  { plNetClientCalibrateTask, "plNetClientCalibrateTask" },
  { plNetMsgDeletePlayer, "plNetMsgDeletePlayer" },
  { plNetServerMsgVaultDeletePlayer, "plNetServerMsgVaultDeletePlayer" },
  { plNetCoreStatsSummary, "plNetCoreStatsSummary" },
  { plCreatableListHelper, "plCreatableListHelper" },
  { plAvTaskSeek, "plAvTaskSeek" },
  { plAGInstanceCallbackMsg, "plAGInstanceCallbackMsg" },
  { plArmatureEffectMsg, "plArmatureEffectMsg" },
  { plArmatureEffectStateMsg, "plArmatureEffectStateMsg" },
  { plShadowCastMsg, "plShadowCastMsg" },
  { plBoundsIsect, "plBoundsIsect" },
  { plNetClientCommLeaveTask, "plNetClientCommLeaveTask" },
  { plResMgrHelperMsg, "plResMgrHelperMsg" },
  { plNetMsgAuthenticateResponse, "plNetMsgAuthenticateResponse" },
  { plNetMsgAccountAuthenticated, "plNetMsgAccountAuthenticated" },
  { plNetClientCommSendPeriodicAliveTask, "plNetClientCommSendPeriodicAliveTask" },
  { plNetClientCommCheckServerSilenceTask, "plNetClientCommCheckServerSilenceTask" },
  { plNetClientCommPingTask, "plNetClientCommPingTask" },
  { plNetClientCommFindAgeTask, "plNetClientCommFindAgeTask" },
  { plNetClientCommSetActivePlayerTask, "plNetClientCommSetActivePlayerTask" },
  { plNetClientCommGetPlayerListTask, "plNetClientCommGetPlayerListTask" },
  { plNetClientCommCreatePlayerTask, "plNetClientCommCreatePlayerTask" },
  { plNetClientCommJoinAgeTask, "plNetClientCommJoinAgeTask" },
  { plVaultAdminInitializationTask, "plVaultAdminInitializationTask" },
  { plSoundVolumeApplicator, "plSoundVolumeApplicator" },
  { plCutter, "plCutter" },
  { plBulletMsg, "plBulletMsg" },
  { plDynaDecalEnableMsg, "plDynaDecalEnableMsg" },
  { plOmniCutoffApplicator, "plOmniCutoffApplicator" },
  { plArmatureUpdateMsg, "plArmatureUpdateMsg" },
  { plAvatarFootMsg, "plAvatarFootMsg" },
  { plNetOwnershipMsg, "plNetOwnershipMsg" },
  { plNetMsgRelevanceRegions, "plNetMsgRelevanceRegions" },
  { plParticleFlockMsg, "plParticleFlockMsg" },
  { plAvatarBehaviorNotifyMsg, "plAvatarBehaviorNotifyMsg" },
  { plATCChannel, "plATCChannel" },
  { plScalarSDLChannel, "plScalarSDLChannel" },
  { plAvatarSetTypeMsg, "plAvatarSetTypeMsg" },
  { plNetMsgLoadClone, "plNetMsgLoadClone" },
  { plNetMsgPlayerPage, "plNetMsgPlayerPage" },
  { plVNodeInitTask, "plVNodeInitTask" },
  { plRippleShapeMsg, "plRippleShapeMsg" },
  { plEventManager, "plEventManager" },
  { plVaultNeighborhoodInitializationTask, "plVaultNeighborhoodInitializationTask" },
  { plNetServerMsgAgentRecoveryRequest, "plNetServerMsgAgentRecoveryRequest" },
  { plNetServerMsgFrontendRecoveryRequest, "plNetServerMsgFrontendRecoveryRequest" },
  { plNetServerMsgBackendRecoveryRequest, "plNetServerMsgBackendRecoveryRequest" },
  { plNetServerMsgAgentRecoveryData, "plNetServerMsgAgentRecoveryData" },
  { plNetServerMsgFrontendRecoveryData, "plNetServerMsgFrontendRecoveryData" },
  { plNetServerMsgBackendRecoveryData, "plNetServerMsgBackendRecoveryData" },
  { plMatrixDifferenceApp, "plMatrixDifferenceApp" },
  { plAvatarSpawnNotifyMsg, "plAvatarSpawnNotifyMsg" },
  /* in PotS the following are all incremented by one */
  { plVaultGameServerInitializationTask, "plVaultGameServerInitializationTask" },
  { plNetClientFindDefaultAgeTask, "plNetClientFindDefaultAgeTask" },
  { plVaultAgeNode, "plVaultAgeNode" },
  { plVaultAgeInitializationTask, "plVaultAgeInitializationTask" },
  { plSetListenerMsg, "plSetListenerMsg" },
  { plVaultSystemNode, "plVaultSystemNode" },
  { plAvBrainSwim, "plAvBrainSwim" },
  { plNetMsgVault, "plNetMsgVault" },
  { plNetServerMsgVault, "plNetServerMsgVault" },
  { plVaultTask, "plVaultTask" },
  { plVaultConnectTask, "plVaultConnectTask" },
  { plVaultNegotiateManifestTask, "plVaultNegotiateManifestTask" },
  { plVaultFetchNodesTask, "plVaultFetchNodesTask" },
  { plVaultSaveNodeTask, "plVaultSaveNodeTask" },
  { plVaultFindNodeTask, "plVaultFindNodeTask" },
  { plVaultAddNodeRefTask, "plVaultAddNodeRefTask" },
  { plVaultRemoveNodeRefTask, "plVaultRemoveNodeRefTask" },
  { plVaultSendNodeTask, "plVaultSendNodeTask" },
  { plVaultNotifyOperationCallbackTask, "plVaultNotifyOperationCallbackTask" },
  { plVNodeMgrInitializationTask, "plVNodeMgrInitializationTask" },
  { plVaultPlayerInitializationTask, "plVaultPlayerInitializationTask" },
  { plNetVaultServerInitializationTask, "plNetVaultServerInitializationTask" },
  { plCommonNeighborhoodsInitTask, "plCommonNeighborhoodsInitTask" },
  { plVaultFolderNode, "plVaultFolderNode" },
  { plVaultImageNode, "plVaultImageNode" },
  { plVaultTextNoteNode, "plVaultTextNoteNode" },
  { plVaultSDLNode, "plVaultSDLNode" },
  { plVaultAgeLinkNode, "plVaultAgeLinkNode" },
  { plVaultChronicleNode, "plVaultChronicleNode" },
  { plVaultPlayerInfoNode, "plVaultPlayerInfoNode" },
  { plVaultMgrNode, "plVaultMgrNode" },
  { plVaultPlayerNode, "plVaultPlayerNode" },
  { plSynchEnableMsg, "plSynchEnableMsg" },
  { plNetVaultServerNode, "plNetVaultServerNode" },
  { plVaultAdminNode, "plVaultAdminNode" },
  { plVaultGameServerNode, "plVaultGameServerNode" },
  { plVaultPlayerInfoListNode, "plVaultPlayerInfoListNode" },
  { plAvatarStealthModeMsg, "plAvatarStealthModeMsg" },
  { plEventCallbackInterceptMsg, "plEventCallbackInterceptMsg" },
  { plDynamicEnvMapMsg, "plDynamicEnvMapMsg" },
  { plIfaceFadeAvatarMsg, "plIfaceFadeAvatarMsg" },
  { plAvBrainClimb, "plAvBrainClimb" },
  { plSharedMeshBCMsg, "plSharedMeshBCMsg" },
  { plNetVoiceListMsg, "plNetVoiceListMsg" },
  { plSwimMsg, "plSwimMsg" },
  { plMorphDelta, "plMorphDelta" },
  { plMatrixControllerCacheChannel, "plMatrixControllerCacheChannel" },
  { plVaultMarkerNode, "plVaultMarkerNode" },
  { pfMarkerMsg, "pfMarkerMsg" },
  { plPipeResMakeMsg, "plPipeResMakeMsg" },
  { plPipeRTMakeMsg, "plPipeRTMakeMsg" },
  { plPipeGeoMakeMsg, "plPipeGeoMakeMsg" },
  { plSimSuppressMsg, "plSimSuppressMsg" },
  { plVaultMarkerListNode, "plVaultMarkerListNode" },
  { plAvTaskOrient, "plAvTaskOrient" },
  { plAgeBeginLoadingMsg, "plAgeBeginLoadingMsg" },
  { pfBackdoorMsg, "pfBackdoorMsg" }, /* plSetNetGroupIDMsg2 */
  { plNetMsgPython, "plNetMsgPython" },
  { pfPythonMsg, "pfPythonMsg" },
  { plStateDataRecord, "plStateDataRecord" },
  { plNetClientCommDeletePlayerTask, "plNetClientCommDeletePlayerTask" },
  { plNetMsgSetTimeout, "plNetMsgSetTimeout" },
  { plNetMsgActivePlayerSet, "plNetMsgActivePlayerSet" },
  { plNetClientCommSetTimeoutTask, "plNetClientCommSetTimeoutTask" },
  { plNetRoutableMsgOmnibus, "plNetRoutableMsgOmnibus" },
  { plNetMsgGetPublicAgeList, "plNetMsgGetPublicAgeList" },
  { plNetMsgPublicAgeList, "plNetMsgPublicAgeList" },
  { plNetMsgCreatePublicAge, "plNetMsgCreatePublicAge" },
  { plNetMsgPublicAgeCreated, "plNetMsgPublicAgeCreated" },
  { plNetServerMsgEnvelope, "plNetServerMsgEnvelope" },
  { plNetClientCommGetPublicAgeListTask, "plNetClientCommGetPublicAgeListTask" },
  { plNetClientCommCreatePublicAgeTask, "plNetClientCommCreatePublicAgeTask" },
  { plNetServerMsgPendingMsgs, "plNetServerMsgPendingMsgs" },
  { plNetServerMsgRequestPendingMsgs, "plNetServerMsgRequestPendingMsgs" },
  { plDbInterface, "plDbInterface" },
  { plDbProxyInterface, "plDbProxyInterface" },
  { plDBGenericSQLDB, "plDBGenericSQLDB" },
  { plMySqlDB, "plMySqlDB" },
  { plNetGenericDatabase, "plNetGenericDatabase" },
  { plNetVaultDatabase, "plNetVaultDatabase" },
  { plNetServerMsgPlsUpdatePlayerReply, "plNetServerMsgPlsUpdatePlayerReply" },
  { plVaultDisconnectTask, "plVaultDisconnectTask" },
  { plNetClientCommSetAgePublicTask, "plNetClientCommSetAgePublicTask" },
  { plNetClientCommRegisterOwnedAge, "plNetClientCommRegisterOwnedAge" },
  { plNetClientCommUnregisterOwnerAge, "plNetClientCommUnregisterOwnerAge" },
  { plNetClientCommRegisterVisitAge, "plNetClientCommRegisterVisitAge" },
  { plNetClientCommUnregisterVisitAge, "plNetClientCommUnregisterVisitAge" },
  { plNetMsgRemovePublicAge, "plNetMsgRemovePublicAge" },
  { plNetMsgPublicAgeRemoved, "plNetMsgPublicAgeRemoved" },
  { plNetClientCommRemovePublicAgeTask, "plNetClientCommRemovePublicAgeTask" },
  { plCCRMessage, "plCCRMessage" },
  { plNetAuthDatabase, "plNetAuthDatabase" }, /* plAvOneShotLinkTask2 */
  { plAvatarOpacityCallbackMsg, "plAvatarOpacityCallbackMsg" },
  { plAGDetachCallbackMsg, "plAGDetachCallbackMsg" },
  { pfMovieEventMsg, "pfMovieEventMsg" },
  { plMovieMsg, "plMovieMsg" },
  { plPipeTexMakeMsg, "plPipeTexMakeMsg" },
  { plEventLog, "plEventLog" },
  { plDbEventLog, "plDbEventLog" },
  { plSyslogEventLog, "plSyslogEventLog" },
  { plCaptureRenderMsg, "plCaptureRenderMsg" },
  { plAgeLoaded2Msg, "plAgeLoaded2Msg" },
  { plPseudoLinkAnimTriggerMsg, "plPseudoLinkAnimTriggerMsg" }, /* plPseudoLinkEffectMsg2 */
  { plPseudoLinkAnimCallbackMsg, "plPseudoLinkAnimCallbackMsg" },
  { plNetMsgSystemView, "plNetMsgSystemView" }, /* plClimbEventMsg2 */
  { plAvBrainQuab, "plAvBrainQuab" }, /* also plNetMsgSystemViewReply */
  { plNetServerMsgSystemView, "plNetServerMsgSystemView" },
  { plNetServerMsgSystemViewReply, "plNetServerMsgSystemViewReply" },
  { plNetServerBasicInfo, "plNetServerBasicInfo" },
  { plNetClientCommSystemViewTask, "plNetClientCommSystemViewTask" },
#endif /* INCLUDE_ALL_TYPES */
  { 0, NULL }
};

static const value_string uu_typecodes[] = {
  { NetMsgActivePlayerSet, "NetMsgActivePlayerSet" },
  { plVaultNodeRef, "plVaultNodeRef" },
  { plVaultNode, "plVaultNode" },
  { 0, NULL }
};

static const value_string pots_typecodes[] = {
  { NetMsgSetTimeout2, "NetMsgSetTimeout2" },
  { plVaultNodeRef2, "plVaultNodeRef2" },
  { plVaultNode2, "plVaultNode2" },
  { 0, NULL }
};

/* GameMessage flags, I don't know what ANY of them are but I need to start
   using them... */
#define GameMsgFlag1  0x00000001
#define GameMsgFlag2  0x00000002
#define GameMsgFlag3  0x00000004
#define GameMsgFlag4  0x00000008
#define GameMsgFlag5  0x00000010
#define GameMsgFlag6  0x00000020
#define GameMsgFlag7  0x00000040
#define GameMsgFlag8  0x00000080
#define GameMsgFlag9  0x00000100
#define GameMsgFlag10 0x00000200
#define GameMsgFlag11 0x00000400
#define GameMsgFlag12 0x00000800
#define GameMsgFlag13 0x00001000
#define GameMsgFlag14 0x00002000
#define GameMsgFlag15 0x00004000
#define GameMsgFlag16 0x00008000
#define GameMsgFlag17 0x00010000

static const value_string eventtypes[] = {
#define kCollisionEvent 1
  { kCollisionEvent, "Collision" },
#define kPickedEvent 2
  { kPickedEvent, "Picked" },
#define kControlKeyEvent 3
  { kControlKeyEvent, "ControlKey" },
#define kVariableEvent 4
  { kVariableEvent, "Variable" },
#define kFacingEvent 5
  { kFacingEvent, "Facing" },
#define kContainedEvent 6
  { kContainedEvent, "Contained" },
#define kActivateEvent 7
  { kActivateEvent, "Activate" },
#define kCallbackEvent 8
  { kCallbackEvent, "Callback" },
#define kResponderStateEvent 9
  { kResponderStateEvent, "ResponderState" },
#define kMultiStageEvent 10
  { kMultiStageEvent, "MultiStage" },
#define kSpawnedEvent 11
  { kSpawnedEvent, "Spawned" },
#define kClickDragEvent 12
  { kClickDragEvent, "ClickDrag" },
#define UnknownNotifyEventType 13
  { UnknownNotifyEventType, "Unknown" },
#define kOfferLinkingBookEvent 14
  { kOfferLinkingBookEvent, "OfferLinkingBook" },
#define kBookEvent 15
  { kBookEvent, "Book" },
  { 0, NULL }
};

static const value_string notifydatatype[] = {
#define kVarNumberType 1
  { kVarNumberType, "Number" },
#define kVarKeyType 2
  { kVarKeyType, "Key" },
  { 0, NULL }
};

static const value_string multistgs[] = {
#define kEnterStage 1
  { kEnterStage, "EnterStage" },
#define kBeginingOfLoop 2
  { kBeginingOfLoop, "BeginingOfLoop" },
#define kAdvanceNextStage 3
  { kAdvanceNextStage, "AdvanceNextStage" },
#define kRegressPrevStage 4
  { kRegressPrevStage, "RegressPrevStage" },
#define kStageExitBrain -1
  { kStageExitBrain, "StageExitBrain" }
};

static const value_string wallstates[] = {
#define kWaiting 0
  { kWaiting, "Waiting" },
#define kNorthSit 1
  { kNorthSit, "NorthSit" },
#define kSouthSit 2
  { kSouthSit, "SouthSit" },
#define kNorthSelect 3
  { kNorthSelect, "NorthSelect" },
#define kSouthSelect 4
  { kSouthSelect, "SouthSelect" },
#define kNorthReady 5
  { kNorthReady, "NorthReady" },
#define kSouthReady 6
  { kSouthReady, "SouthReady" },
#define kNorthPlayerEntry 7
  { kNorthPlayerEntry, "NorthPlayerEntry" },
#define kSouthPlayerEntry 8
  { kSouthPlayerEntry, "SouthPlayerEntry" },
#define kGameInProgress 9
  { kGameInProgress, "GameInProgress" },
#define kNorthWin 10
  { kNorthWin, "NorthWin" },
#define kSouthWin 11
  { kSouthWin, "SouthWin" },
#define kSouthQuit 12
  { kSouthQuit, "SouthQuit" },
#define kNorthQuit 13
  { kNorthQuit, "NorthQuit" }
};

static const value_string wallmsgs[] = {
#define kNewState 0
  { kNewState, "NewState" },
#define kAddBlocker 1
  { kAddBlocker, "AddBlocker" },
#define kRemoveBlocker 2
  { kRemoveBlocker, "RemoveBlocker" },
#define kSetBlockerNum 3
  { kSetBlockerNum, "SetBlockerNum" },
#define kTotalGameState 4
  { kTotalGameState, "TotalGameState" },
#define kEndGameState 5
  { kEndGameState, "EndGameState" },
#define kRequestGameState 6
  { kRequestGameState, "RequestGameState" },
};

static const true_false_string north_south = {
  "North",
  "South"
};

static const value_string vaultops[] = {
  { VConnect, "Connect" },
  { VDisconnect, "Disconnect" },
  { VAddNodeRef, "AddNodeRef" },
  { VRemoveNodeRef, "RemoveNodeRef" },
  { VNegotiateManifest, "NegotiateManifest" },
  { VSaveNode, "SaveNode" },
  { VFindNode, "FindNode" },
  { VFetchNode, "FetchNode" },
  { VSendNode, "SendNode" },
  { VSetSeen, "SetSeen" },
  { VOnlineState, "OnlineState" },
  { 0, NULL}
};

static const value_string vvalformats[] = {
  { DInteger, "Integer" },
  { DFloat, "Float" },
  { DBool, "Bool" },
  { DUruString, "UruString" },
  { DPlKey, "PlKey" },
  { DStruct, "Struct" },
  { DCreatable, "Creatable" },
  { DTimestamp, "Timestamp" },
  { DTime, "Time" },
  { DByte, "Byte" },
  { DShort, "Short" },
  { DAgeTimeOfDay, "AgeTimeOfDay" },
  { DVector3, "Vector3" },
  { DPoint3, "Point3" },
  { DQuaternion, "Quaternion" },
  { DRGB8, "RGB8" },
  { 0, NULL }
};

static const value_string vnodetypes[] = {
  { KInvalidNode, "InvalidNode" },
  { KVNodeMgrPlayerNode, "VNodeMgrPlayerNode" },
  { KVNodeMgrAgeNode, "VNodeMgrAgeNode" },
  { KVNodeMgrGameServerNode, "VNodeMgrGameServerNode" },
  { KVNodeMgrAdminNode, "VNodeMgrAdminNode" },
  { KVNodeMgrServerNode, "VNodeMgrServerNode" },
  { KVNodeMgrCCRNode, "VNodeMgrCCRNode" },
  { KFolderNode, "FolderNode" },
  { KPlayerInfoNode, "PlayerInfoNode" },
  { KSystem, "System" },
  { KImageNode, "ImageNode" },
  { KTextNoteNode, "TextNoteNode" },
  { KSDLNode, "SDLNode" },
  { KAgeLinkNode, "AgeLinkNode" },
  { KChronicleNode, "ChronicleNode" },
  { KPlayerInfoListNode, "PlayerInfoListNode" },
  { KMarkerNode, "MarkerNode" },
  { KAgeInfoNode, "AgeInfoNode" },
  { KAgeInfoListNode, "AgeInfoListNode" },
  { KMarkerListNode, "MarkerListNode" },
  { 0, NULL }
};

static const value_string vfoldertypes[] = {
  { KGeneric, "Generic" },
  { KInboxFolder, "InboxFolder" },
  { KBuddyListFolder, "BuddyListFolder" },
  { KIgnoreListFolder, "IgnoreListFolder" },
  { KPeopleIKnowAboutFolder, "PeopleIKnowAboutFolder" },
  { KVaultMgrGlobalDataFolder, "VaultMgrGlobalDataFolder" },
  { KChronicleFolder, "ChronicleFolder" },
  { KAvatarOutfitFolder, "AvatarOutfitFolder" },
  { KAgeTypeJournalFolder, "AgeTypeJournalFolder" },
  { KSubAgesFolder, "SubAgesFolder" },
  { KDeviceInboxFolder, "DeviceInboxFolder" },
  { KHoodMembersFolder, "HoodMembersFolder" },
  { KAllPlayersFolder, "AllPlayersFolder" },
  { KAgeMembersFolder, "AgeMembersFolder" },
  { KAgeJournalsFolder, "AgeJournalsFolder" },
  { KAgeDevicesFolder, "AgeDevicesFolder" },
  { KAgeInstaceSDLNode, "AgeInstanceSDLNode" },
  { KAgeGlobalSDLNode, "AgeGlobalSDLNode" },
  { KCanVisitFolder, "CanVisitFolder" },
  { KAgeOwnersFolder, "AgeOwnersFolder" },
  { KAllAgeGlobalSDLNodesFolder, "AllAgeGlobalSDLNodesFolder" },
  { KPlayerInfoNodeFolder, "PlayerInfoNodeFolder" },
  { KPublicAgesFolder, "PublicAgesFolder" },
  { KAgesIOwnFolder, "AgesIOwnFolder" },
  { KAgesICanVisitFolder, "AgesICanVisitFolder" },
  { KAvatarClosetFolder, "AvatarClosetFolder" },
  { KAgeInfoNodeFolder, "AgeInfoNodeFolder" },
  { KSystemNode, "SystemNode" },
  { KPlayerInviteFolder, "PlayerInviteFolder" },
  { KCCRPlayersFolder, "CCRPlayersFolder" },
  { KGlobalInboxFolder, "GlobalInboxFolder" },
  { KChildAgesFolder, "ChildAgesFolder" },
#ifdef INCLUDE_LIVE
#define KGameScoresFolder 32
  { KGameScoresFolder, "GameScoresFolder" },
#endif
  { 0, NULL }
};

static const value_string vtasks[] = {
  { TCreatePlayer, "CreatePlayer" },
  { TDeletePlayer, "DeletePlayer" },
  { TGetPlayerList, "GetPlayerList" },
  { TCreateNeighborhood, "CreateNeighborhood" },
  { TJoinNeighborhood, "JoinNeighborhood" },
  { TSetAgePublic, "SetAgePublic" },
  { TIncPlayerOnlineTime, "IncPlayerOnlineTime" },
  { TEnablePlayer, "EnablePlayer" },
  { TRegisterOwnedAge, "RegisterOwnedAge" },
  { TUnRegisterOwnedAge, "UnRegisterOwnedAge" },
  { TRegisterVisitAge, "RegisterVisitAge" },
  { TUnRegisterVisitAge, "UnRegisterVisitAge" },
  { TFriendInvite, "FriendInvite" },
  { 0, NULL }
};

#define cRelRegFerry 0x00000100
#define cRelRegGreatStair 0x00000200
#define cRelRegKahloPub 0x00000800
#define cRelRegCourtyard 0x00000020
#define cRelRegDakotahAlley 0x00000040
#define cRelRegMuseumAlley 0x00000080
#define cRelRegPalace01 0x00008000
#define cRelRegPalace02 0x00010000
#define cRelRegCaveTJunction 0x00000010
#define cRelRegCanyon 0x00000008 /* unsure */
#define cRelRegConcertHall 0x00000004
#define cRelRegBridgeStairs 0x00000002 /* unsure */ /* bridge _and_ stairs */
#define cRelRegLibraryWalk 0x00001000
#define cRelRegLibraryStairs 0x00002000 /* between T and library courtyard */
#define cRelRegLibraryExt 0x00004000
#define cRelRegKadishGallery 0x00000400

#define cRelRegDefaultMaybe 0x00000001


#if 0
static const value_string behaviortypes[] = {
#define kBehaviorTypeStandingJump	0x00000001
#define kBehaviorTypeWalkingJump	0x00000002
#define kBehaviorTypeRunningJump	0x00000004
 #define kBehaviorTypeAnyJump		0x00000007
#define kBehaviorTypeRunningImpact	0x00000008
#define kBehaviorTypeGroundImpact	0x00000010
 #define kBehaviorTypeAnyImpact		0x00000018
#define kBehaviorTypeIdle		0x00000020
#define kBehaviorTypeWalk		0x00000040
#define kBehaviorTypeRun		0x00000080
#define kBehaviorTypeWalkBack		0x00000100
#define kBehaviorTypeTurnLeft		0x00000200
#define kBehaviorTypeTurnRight		0x00000400
#define kBehaviorTypeSidestepLeft	0x00000800
#define kBehaviorTypeSidestepRight	0x00001000
#define kBehaviorTypeFall		0x00002000
#define kBehaviorTypeMovingTurnLeft	0x00004000
#define kBehaviorTypeMovingTurnRight	0x00008000
#define kBehaviorTypeLinkIn		0x00010000
#define kBehaviorTypeLinkOut		0x00020000
};
static const value_string bookevents[] = {
#define kNotifyImageLink 0
#define kNotifyShow 1
#define kNotifyHide 2
#define kNotifyNextPage 3
#define kNotifyPreviousPage 4
#define kNotifyCheckUnchecked 5
#define kNotifyClose 6
};
static const value_string brainmodes[] = {
#define kGeneric 0
#define kLadder 1
#define kSit 2
#define kEmote 3
#define kAFK 4
#define kNonGeneric 5
};
static const value_string notifytype[] = {
#define kActivator 0
#define kVarNotify 1
#define kNotifySelf 2
#define kResponderFF 3
#define kResponderChangeState 4
};
static const value_string SDLvartypes[] = {
#define kInt 0
#define kFloat 1
#define kBool 2
#define kString32 3
#define kKey 4
#define kStateDescriptor 5
#define kCreatable 6
#define kDouble 7
#define kTime 8
#define kByte 9
#define kShort 10
#define kVector3 50
#define kPoint3 51
#define kRGB 52
#define kRGBA 53
#define kQuaternion 54
#define kNone -1
};
static const value_string clothingitems[] = {
#define kAnyClothingItem -1
#define kPantsClothingItem 0
#define kShirtClothingItem 1
#define kLeftHandClothingItem 2
#define kRightHandClothingItem 3
#define kFaceClothingItem 4
#define kHairClothingItem 5
#define kLeftFootClothingItem 6
#define kRightFootClothingItem 7
#define kAccessoryClothingItem 8
};
#endif


static hf_register_info hf[] = {
  { &hf_uru_incomplete_dissection,
    { "Dissection incomplete", "uru.incomplete",
      FT_BOOLEAN, 8, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_dissection_error,
    { "Dissection error", "uru.error",
      FT_BOOLEAN, 8, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_header,
    { "Uru Header", "uru.header",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "The Uru header", HFILL }
  },
  { &hf_uru_flag,
    { "Uru Protocol ID", "uru.id",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "The Uru protocol magic number", HFILL }
  },
  { &hf_uru_validation_type,
    { "Uru Validation Type", "uru.valtype",
      FT_UINT8, BASE_DEC, VALS(validtypenames), 0x0,
      "The message validation type", HFILL }
  },
  { &hf_uru_checksum,
    { "Uru Checksum", "uru.cksum",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "32-bit checksum", HFILL }
  },
  /* info gleaned from uru_get_header(unet3) => tUnetUruMsg::store(unet3+) */
  { &hf_uru_packetnum,
    { "Packet Number", "uru.pn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Packet counter (unique)", HFILL }
  },
  { &hf_uru_msgtype,
    { "Message Type Flags", "uru.tf",
      /*FT_BYTES, BASE_NONE, NULL, 0x0,*/
      FT_UINT8, BASE_HEX, VALS(messagetypes), 0x0,
      "Specifies the message type and whether an ack is required", HFILL }
  },
  { &hf_uru_unkA,
    { "Unknown A", "uru.unka",				/* == Alcugs */
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Unknown (should be 0)", HFILL }
  },
  { &hf_uru_fragnum,
    { "Fragment Number", "uru.frn",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Which fragment this packet is", HFILL }
  },
  { &hf_uru_msgnum,
    { "Message Number", "uru.sn",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "The sequence number of the message this packet belongs to", HFILL }
  },
  { &hf_uru_fragct,
    { "Fragment Count", "uru.frt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "The number of fragments in the message this packet belongs to", HFILL }
  },
  { &hf_uru_unkB,
    { "Unknown B", "uru.unkb",				/* == Alcugs */
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Unknown (should be 0)", HFILL }
  },
  { &hf_uru_fragack,
    { "Previous Fragment Ack Required", "uru.pfr",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "The fragment number of the previous packet requiring an ack", HFILL }
  },
  { &hf_uru_lastack,
    { "Previous Ack Required", "uru.ps",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "The previous packet requiring an ack", HFILL }
  },
  { &hf_uru_msglen,
    { "Packet Length", "uru.size",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "The length of the packet, or the number of acks for Ack messages", HFILL }
  },
  /* data next */

  /* 0x42: negotiations: parse_negotiation(unet3)
       => tmNetClientComm::store(unet3+) */
  { &hf_uru_bandwidth,
    { "Bandwidth", "uru.nego.bw",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_nego_ts,
    { "Timestamp", "uru.nego.ts",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_nego_sec,
    { "Timestamp (sec)", "uru.nego.sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_nego_usec,
    { "Timestamp (microsec)", "uru.nego.usec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },

  /* 0x80: acks: ack_update(unet3) => ackCheck(unet3+) */
  { &hf_uru_ack_frn,
    { "Acked fragment number", "uru.ack.frn",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ack_sn,
    { "Acked message number", "uru.ack.sn",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ack_frnf,
    { "Previous acked fragment number", "uru.ack.frnf",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ack_snf,
    { "Previous acked message number", "uru.ack.snf",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ack_zero,
    { "Unknown zero data", "uru.ack.zero",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ack,
    { "Ack", "uru.ack",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },

  /* 0x02, 0x00: info gleaned from parse_plNet_msg(unet3)
     => tmMsgBase::store(unet3+) */
  { &hf_uru_cmd,
    { "Command", "uru.cmd",
      FT_UINT16, BASE_HEX, VALS(plNetMsgs), 0x0,
      "Which kind of NetMsg this is", HFILL }
  },
  { &hf_uru_flags,
    { "NetMsg Flags", "uru.flags",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "Flags for what is included in the NetMsg header", HFILL }
  },
#define plFlagsMaybeNotify 0x00000002
#define plFlagsMaybeAvatarState 0x00002000 /* plAvatarInputState & physical SDLStateBCast; maybe means "expedite"? */
  { &hf_uru_flags_ts,
    { "Timestamp included", "uru.flags.ts",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetTimestamp,
      "", HFILL }
  },
  { &hf_uru_flags_notify,
    { "Notify?", "uru.flags.notify",
      FT_BOOLEAN, 32, NULL, plFlagsMaybeNotify,
      "", HFILL }
  },
  { &hf_uru_flags_ip,
    { "IP address included", "uru.flags.ip",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetIP,
      "", HFILL }
  },
  { &hf_uru_flags_firewalled,
    { "Firewalled", "uru.flags.firewalled",
      FT_BOOLEAN, 32, NULL, plNetFirewalled,
      "", HFILL }
  },
  { &hf_uru_flags_X,
    { "X included", "uru.flags.X",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetX,
      "", HFILL }
  },
  { &hf_uru_flags_bcast,
    { "Broadcast", "uru.flags.bcast",
      FT_BOOLEAN, 32, NULL, plNetBcast,
      "", HFILL }
  },
  { &hf_uru_flags_statereq,
    { "State Request?", "uru.flags.statereq",
      FT_BOOLEAN, 32, NULL, plNetStateReq,
      "", HFILL }
  },
  { &hf_uru_flags_ki,
    { "KI included", "uru.flags.ki",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetKi,
      "", HFILL }
  },
  { &hf_uru_flags_avstate,
    { "Avatar State?", "uru.flags.avstate",
      FT_BOOLEAN, 32, NULL, plFlagsMaybeAvatarState,
      "", HFILL }
  },
  { &hf_uru_flags_guid,
    { "GUID included", "uru.flags.guid",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetGUI,
      "", HFILL }
  },
  { &hf_uru_flags_directed,
    { "Directed?", "uru.flags.directed",
      FT_BOOLEAN, 32, NULL, plNetDirected,
      "", HFILL }
  },
  { &hf_uru_flags_version,
    { "Version included", "uru.flags.version",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetVersion,
      "", HFILL }
  },
  { &hf_uru_flags_custom,
    { "Custom?", "uru.flags.custom",
      FT_BOOLEAN, 32, NULL, plNetCustom,
      "", HFILL }
  },
  { &hf_uru_flags_ack,
    { "Ack required", "uru.flags.ack",
      FT_BOOLEAN, 32, NULL, plNetAck,
      "", HFILL }
  },
  { &hf_uru_flags_sid,
    { "SID included", "uru.flags.sid",
      FT_BOOLEAN, 32, TFS(&yes_no), plNetSid,
      "", HFILL }
  },
  { &hf_uru_flags_p2p,
    { "P2P?", "uru.flags.p2p",
      FT_BOOLEAN, 32, NULL, plNetP2P,
      "", HFILL }
  },
#define plFlagsUnknown (int)~(plNetTimestamp|plNetIP|plNetFirewalled|plNetX|plNetBcast|plNetStateReq|plNetKi|plNetGUI|plNetDirected|plNetVersion|plNetCustom|plNetAck|plNetSid|plNetP2P|plFlagsMaybeNotify|plFlagsMaybeAvatarState)
  { &hf_uru_flags_unk,
    { "Unknown?", "uru.flags.unk",
      FT_BOOLEAN, 32, NULL, plFlagsUnknown,
      "", HFILL }
  },
  { &hf_uru_version,
    { "Version info", "uru.version",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_maxversion,
    { "Max version", "uru.maxv",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_minversion,
    { "Min version", "uru.minv",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ts,
    { "Timestamp", "uru.ts",
      /* FT_RELATIVE_TIME doesn't work */
      /*FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,*/
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ts_sec,
    { "Timestamp (sec)", "uru.ts.sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ts_usec,
    { "Timestamp (microsec)", "uru.ts.usec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_X,
    { "X", "uru.x",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_KI,
    { "KI", "uru.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "KI number", HFILL }
  },
  { &hf_uru_GUID,
    { "GUID", "uru.guid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Player GUID", HFILL }
  },
  { &hf_uru_IPaddr,
    { "IP address", "uru.ip",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_port,
    { "Port", "uru.port",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sid, /* custom flag (see unet3+) */
    { "SID", "uru.sid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_isfrag,
    { "Fragment info", "uru.isfrag",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_msgbody,
    { "Message body", "uru.msgbody",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },

  /* plNetMessages */
  { &hf_uru_age_flags,
    { "Flags", "uru.age.flags",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_contents,
    { "Contents", "uru.age.cts",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_cfname,
    { "Filename", "uru.age.cfname",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x01,
      "", HFILL }
  },
  { &hf_uru_age_ciname,
    { "Instance name", "uru.age.ciname",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x02,
      "", HFILL }
  },
  { &hf_uru_age_cguid,
    { "GUID", "uru.age.cguid",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x04,
      "", HFILL }
  },
  { &hf_uru_age_cuname,
    { "User defined name", "uru.age.cuname",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x08,
      "", HFILL }
  },
  { &hf_uru_age_cinstance,
    { "Instance number", "uru.age.cinst",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x10,
      "", HFILL }
  },
  { &hf_uru_age_cdname,
    { "Display name", "uru.age.cdname",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x20,
      "", HFILL }
  },
  { &hf_uru_age_clang,
    { "Language", "uru.age.clang",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x40,
      "", HFILL }
  },
  { &hf_uru_age_cunk,
    { "Unknown", "uru.age.cunk",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x80,
      "", HFILL }
  },
  { &hf_uru_age_fname,
    { "Filename", "uru.age.fname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_iname,
    { "Instance name", "uru.age.iname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_guid,
    { "GUID", "uru.age.guid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_uname,
    { "User defined name", "uru.age.uname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_instance,
    { "Instance number", "uru.age.inst",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_dname,
    { "Display name", "uru.age.dname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_lang,
    { "Language", "uru.age.lang",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_rules,
    { "Linking rules", "uru.age.rules",
      FT_UINT8, BASE_HEX, VALS(linkingrules), 0x0,
      "", HFILL }
  },
  { &hf_uru_age_unk1,
    { "0x00000001", "uru.age.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_spawncts,
    { "Spawn info", "uru.age.spawncts",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_spawnpt,
    { "Spawn point", "uru.age.spawnpt",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_linkpt,
    { "Link point", "uru.age.linkpt",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_camera,
    { "Camera stack", "uru.age.camera",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_unk2,
    { "(unknown)", "uru.age.unk2",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_age_extra,
    { "Extra", "uru.age.extra",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_exists,
    { "Exists", "uru.obj.exists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj,
    { "Object", "uru.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_flags,
    { "Flags", "uru.obj.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_pageid,
    { "Page ID", "uru.obj.pageid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_pagetype,
    { "Page type", "uru.obj.pagetype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_extra,
    { "Extra", "uru.obj.extra",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_type,
    { "Object Type", "uru.obj.type",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_name,
    { "Object Name", "uru.obj.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_index,
    { "Index", "uru.obj.index",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_obj_clientid,
    { "Client ID", "uru.obj.clientid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_exists, /* was unk7 in Alcugs for LoadClone */
    { "  Exists", "uru.subobj.exists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj,
    { "  Object", "uru.subobj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_flags,
    { "  Flags", "uru.subobj.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_pageid,
    { "  Page ID", "uru.subobj.pageid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_pagetype,
    { "  Page type", "uru.subobj.pagetype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_extra,
    { "  Extra", "uru.subobj.extra",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_type,
    { "  Object Type", "uru.subobj.type",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_name,
    { "  Object Name", "uru.subobj.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_index,
    { "  Index", "uru.subobj.index",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subobj_clientid,
    { "  Client ID", "uru.subobj.clientid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_node_trackid,
    { "Track node ID", "uru.node.trackid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Use this to track all occurrences of a node", HFILL }
  },

  /* NetMsgJoinAck */
  { &hf_uru_join_unkflag,
    { "Unknown flag", "uru.join.unkflag",		/* == Alcugs */
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgJoinAck */
  /* NetMsgSDLState */
  /* NetMsgSDLStateBCast */
  { &hf_uru_sdl_uncsize,
    { "Uncompressed size", "uru.sdl.uncsize",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_cflag,
    { "Compression", "uru.sdl.cflag",
      FT_UINT8, BASE_HEX, VALS(compflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sdllen,
    { "SDL length", "uru.sdl.sdllen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sdlversion,
    { "SDL version", "uru.sdl.sdlver",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sdlname,
    { "SDL name", "uru.sdl.sdlname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_eflag,
    { "Some flag", "uru.sdl.eflag",
      FT_UINT16, BASE_HEX, VALS(sdlflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_unk6,
    { "0x06", "uru.sdl.unk06",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_name,
    { "Name", "uru.sdl.name",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sdlct,
    { "Number of SDL variables", "uru.sdl.sdlct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sub,
    { "Sub SDL", "uru.sdl.subsdl",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sdlsct,
    { "Number of SDL structures", "uru.sdl.sdlsct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_tagflag,
    { "Tag flag", "uru.sdl.tagflag",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_stbzero,
    { "Supposed to be zero", "uru.sdl.stbzero",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_tagstring,
    { "Tag string", "uru.sdl.tag",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_entryflags,
    { "Flags", "uru.sdl.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_timestamp,
    { "Timestamp", "uru.sdl.ts",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_ts_sec,
    { "Timestamp (sec)", "uru.sdl.sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_ts_usec,
    { "Timestamp (microsec)", "uru.sdl.usec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_varidx,
    { "SDL variable index", "uru.sdl.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_arrct,
    { "Array size", "uru.sdl.arrct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_default,
    { "Value", "uru.sdl.val.default",
      FT_BOOLEAN, 1, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_arr,
    { "Value", "uru.sdl.val",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_int,
    { "Value", "uru.sdl.val",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_float,
    { "Value", "uru.sdl.val",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_bool,
    { "Value", "uru.sdl.val",
      FT_BOOLEAN, 8, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_byte,
    { "Value", "uru.sdl.val",
      FT_INT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_short,
    { "Value", "uru.sdl.val",
      FT_INT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_str,
    { "Value", "uru.sdl.val",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_obj,
    { "Object", "uru.sdl.val",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_time,
    { "Time", "uru.sdl.val",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_sec,
    { "Time (sec)", "uru.sdl.val.sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_usec,
    { "Time (microsec)", "uru.sdl.val.usec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_x,
    { "x", "uru.sdl.val.x",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_y,
    { "y", "uru.sdl.val.y",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_z,
    { "z", "uru.sdl.val.z",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_3tuple,
    { "Value", "uru.sdl.val",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_qa,
    { "a", "uru.sdl.val.a",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_qb,
    { "b", "uru.sdl.val.b",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_qc,
    { "c", "uru.sdl.val.c",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_qd,
    { "d", "uru.sdl.val.d",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_quat,
    { "Quaternion", "uru.sdl.val",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_r,
    { "Red", "uru.sdl.val.r",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_g,
    { "Green", "uru.sdl.val.g",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_b,
    { "Blue", "uru.sdl.val.b",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_val_clr,
    { "Color", "uru.sdl.val.clr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sub_ct,
    { "Sub SDL count", "uru.sdl.sub.ct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_sub_unk,
    { "Sub SDL record lead", "uru.sdl.sub.unk",
      FT_INT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_phys_mgr,
    { "Manager", "uru.sdl.phys.mgr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_cl_linkeff,
    { "Link effect", "uru.sdl.cl.linkeff",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_cl_item,
    { "Clothing item", "uru.sdl.cl.item",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_morph,
    { "Morph", "uru.sdl.morph",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_unk01,
    { "Unknown byte", "uru.sdl.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_unk02,
    { "Unknown bytes", "uru.sdl.unk0",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_sdl_endthing,
    { "End thing", "uru.sdl.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgLeave */
  { &hf_uru_leave_reason,
    { "Leave reason", "uru.leave.reason",
      FT_UINT8, BASE_DEC, VALS(leavereasons), 0x0,
      "", HFILL }
  },
  /* NetMsgTerminated */
  { &hf_uru_term_reason,
    { "Terminated reason", "uru.term.reason",
      FT_UINT8, BASE_DEC, VALS(termreasons), 0x0,
      "", HFILL }
  },
  /* NetMsgPing */
  { &hf_uru_ping_mtime,
    { "Ping timestamp", "uru.ping.time",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ping_dest,
    { "Ping destination", "uru.ping.dest",
      FT_UINT8, BASE_HEX, VALS(destinations), 0x0,
      "", HFILL }
  },
  /* NetMsgAuthenticateHello */
  { &hf_uru_auth_login,
    { "Login name", "uru.auth.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_auth_maxpacket,
    { "Max packet size", "uru.auth.maxpacket",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_auth_release,
    { "Release number", "uru.auth.release",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgAuthenticateChallenge */
  { &hf_uru_auth_resp,
    { "Auth response", "uru.auth.resp",
      FT_UINT8, BASE_DEC, VALS(authresponses), 0x0,
      "", HFILL }
  },
  /* NetMsgAuthenticateResponse */
  { &hf_uru_auth_hash,
    { "Hash", "uru.auth.hash",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgAccountAuthenticated */
  { &hf_uru_auth_sguid,
    { "Server GUID", "uru.auth.sguid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgVaultPlayerList */
  { &hf_uru_plist_ct,
    { "Number of players", "uru.plist.count",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_plist,
    { "Player:", "uru.plist",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_plist_ki,
    { "  KI number", "uru.plist.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_plist_name,
    { "  Avatar name", "uru.plist.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_plist_flags,
    { "  Flags", "uru.plist.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_plist_url,
    { "URL", "uru.plist.url",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgSetMyActivePlayer */
  { &hf_uru_setact_name,
    { "Avatar name", "uru.setact.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_setact_code,
    { "Code", "uru.plist.code",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgFindAgeReply */
  { &hf_uru_findrply_unk1f,
    { "Code?", "uru.findrply.unk1f",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_findrply_name,
    { "Age (file) name", "uru.findrply.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_findrply_srvtype,
    { "Server type", "uru.findrply.srvtype",
      FT_UINT8, BASE_HEX, VALS(destinations), 0x0,
      "", HFILL }
  },
  { &hf_uru_findrply_server,
    { "Server address", "uru.findrply.server",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_findrply_port,
    { "Port", "uru.findrply.port",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_findrply_guid,
    { "GUID", "uru.findrply.guid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgPagingRoom */
  { &hf_uru_pageroom_format,
    { "Format", "uru.pagerm.format",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pageroom_pageid,
    { "Page ID", "uru.pagerm.pageid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pageroom_pagetype,
    { "Page type", "uru.pagerm.pagetype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pageroom_pagename,
    { "Page name", "uru.pagerm.pagename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pageroom_page,
    { "Flags", "uru.pagerm.page",
      FT_UINT8, BASE_DEC, VALS(pageflags), 0x0,
      "", HFILL }
  },
  /* NetMsgGroupOwner */
  { &hf_uru_groupown_mask,
    { "Mask", "uru.groupown.mask",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_groupown_pageid,
    { "Page ID", "uru.groupown.pageid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_groupown_pagetype,
    { "Page type", "uru.groupown.pagetype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_groupown_unk0,
    { "Unknown", "uru.groupown.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_groupown_flags,
    { "Owner", "uru.groupown.flags",
      FT_BOOLEAN, 8, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgLoadClone */
  { &hf_uru_loadclone_unk1,				/* == Alcugs */
    { "Uncompressed size", "uru.loadclone.unk1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_unk2,				/* == Alcugs */
    { "Compression", "uru.loadclone.unk2",
      FT_UINT8, BASE_HEX, VALS(compflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_sublen,
    { "Submessage length", "uru.loadclone.sublen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subtype,
    { "  Submessage type", "uru.loadclone.subtype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk0,				/* == Alcugs */
    { "  Submsg unknown 0", "uru.loadclone.subunk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk1,				/* == Alcugs */
    { "  Submsg unknown 1", "uru.loadclone.subunk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_netmgrexists,
    { "  NetMgr exists", "uru.loadclone.netmgrexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_netmgr,
    { "  NetMgr", "uru.loadclone.netmgr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk4,				/* == Alcugs */
    { "  Submsg unknown 4", "uru.loadclone.subunk4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk5,				/* == Alcugs */
    { "  Submsg unknown 5", "uru.loadclone.subunk5",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk6,				/* == Alcugs */
    { "  Submsg unknown 6", "uru.loadclone.subunk6",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_avmgrexists,
    { "  AvatarMgr exists", "uru.loadclone.avmgrexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_avmgr,
    { "  AvatarMgr", "uru.loadclone.avmgr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_id,
    { "  ID", "uru.loadclone.id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_parentid,
    { "  Parent ID?", "uru.loadclone.parentid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk11,				/* == Alcugs */
    { "  Submsg unknown 11", "uru.loadclone.subunk11",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subpage,
    { "  Submsg page flag", "uru.loadclone.subpage",
      FT_UINT8, BASE_DEC, VALS(cloneflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subctype,
    { "  Submsg creator type", "uru.loadclone.subctype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk13,
    { "  Submsg unknown 13", "uru.loadclone.subunk13",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subexists,
    { "  Submsg extra object exists", "uru.loadclone.subexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subobj,
    { "  Submsg extra object", "uru.loadclone.subobj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_subunk13a,
    { "  Submsg unknown 13 part 2", "uru.loadclone.unk13a",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_unk3,				/* == Alcugs */
    { "Unknown 3", "uru.loadclone.unk3",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_unk4,				/* == Alcugs */
    { "Unknown 4", "uru.loadclone.unk4",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_page, /* was unk5 */
    { "Page flag", "uru.loadclone.page",
      FT_UINT8, BASE_DEC, VALS(cloneflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_loadclone_init,
    { "For initial age state", "uru.loadclone.init",
      FT_BOOLEAN, 8, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgPlayerPage */
  { &hf_uru_ppage_page,
    { "Page flag", "uru.ppage.page",
      FT_UINT8, BASE_DEC, VALS(pageflags), 0x0,
      "", HFILL }
  },
  /* NetMsgGameStateRequest */
  { &hf_uru_gsreq_ct,
    { "Count", "uru.gsreq.ct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gsreq_pageid,
    { "Page ID", "uru.gsreq.pageid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gsreq_pagetype,
    { "Page Type", "uru.gsreq.pagetype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gsreq_name,
    { "Name", "uru.gsreq.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgInitialAgeStateSent */
  { &hf_uru_stsent_num,
    { "Number of messages", "uru.stsent.num",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgMemberUpdate */
  /* NetMsgMembersList */
  { &hf_uru_mlist_ct,
    { "Number of players", "uru.mlist.ct",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_unkflags,
    { "  Unknown flags", "uru.mlist.unkflags",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_cts,
    { "  Contents", "uru.mlist.cts",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_ki,
    { "  KI", "uru.mlist.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_name,
    { "  Name", "uru.mlist.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_buildtype,
    { "  Build type", "uru.mlist.buildtype",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_ip,
    { "  IP address", "uru.mlist.ip",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_port,
    { "  Port", "uru.mlist.port",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_player,
    { "Player", "uru.mlist.player",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_vis,
    { "  Visibility", "uru.mlist.vis",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_key,
    { "  Key", "uru.mlist.key",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_mlist_page,
    { "Page flags", "uru.mlist.page",
      FT_UINT8, BASE_DEC, VALS(cloneflags), 0x0,
      "", HFILL }
  },
  /* NetMsgSetTimeout */
  { &hf_uru_timeout,
    { "Timeout", "uru.timeout",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgTestAndSet */
  { &hf_uru_test_flag1,					/* == Alcugs */
    { "Flag 1", "uru.test.flag1",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_unk1,					/* == Alcugs */
    { "Unknown 1", "uru.test.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_msglen,
    { "Message length", "uru.test.msglen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_type,
    { "Type", "uru.test.type",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_unk3,					/* == Alcugs */
    { "Unknown 3", "uru.test.unk3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_state1,				/* == Alcugs */
    { "State 1", "uru.test.state1",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_state,
    { "State", "uru.test.state",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_flag2,					/* == Alcugs */
    { "Flag 2", "uru.test.flag2",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_state2,				/* == Alcugs */
    { "State 2", "uru.test.state2",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_test_endthing,
    { "End thing", "uru.test.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgVoice */
  { &hf_uru_voice_unk0,
    { "Unknown 0", "uru.voice.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_voice_unk1,
    { "Unknown 1", "uru.voice.unk1",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_voice_msglen,
    { "Message length", "uru.voice.msglen",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_voice_data,
    { "Voice Data", "uru.voice.data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_voice_recipct,
    { "Recipients", "uru.voice.recipct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_voice_recip,
    { "  ", "uru.voice.recip",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgVault, NetMsgVault2, NetMsgVaultTask */
  { &hf_uru_vault_cmd,
    { "Command", "uru.vault.cmd",
      FT_UINT8, BASE_HEX, VALS(vaultops), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_task,
    { "Task", "uru.vault.task",
      FT_UINT8, BASE_HEX, VALS(vtasks), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_result,
    { "Result", "uru.vault.result",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cflag,
    { "Compression", "uru.vault.cflag",
      FT_UINT8, BASE_HEX, VALS(vcompflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_uncsize,
    { "Uncompressed size", "uru.vault.uncsize",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_msglen,
    { "Message length", "uru.vault.msglen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_itemct,
    { "Items", "uru.vault.items",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_id,
    { "ID", "uru.vault.id",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_dtype,
    { "Data type", "uru.vault.dtype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cgv_format,
    { " Format", "uru.vault.cgv.format",
      FT_UINT8, BASE_HEX, VALS(vvalformats), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cgv_int,
    { " Value", "uru.vault.cgv.val",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cgv_str,
    { " Value", "uru.vault.cgv.val",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cgv_ts,
    { " Value (timestamp)", "uru.vault.cgv.val",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cs_len,
    { " Length", "uru.vault.cs.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_cs_stream,
    { " Stream", "uru.vault.cs.stream",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_nego_ct4,
    { "Count", "uru.vault.nego.count",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_nego_ct2,
    { "Count", "uru.vault.nego.count",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_nego_node,
    { "  ", "uru.vault.nego.node",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_nego_ref,
    { "  ", "uru.vault.nego.ref",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_nego_nodeidx,
    { "  ", "uru.vault.nego.nodeid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_sguid,
    { " Server GUID", "uru.vault.sguid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ref_id1,
    { "  id1", "uru.vault.ref.id1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ref_id2,
    { "  id2", "uru.vault.ref.id2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ref_id3,
    { "  id3", "uru.vault.ref.id3",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ref_flag,
    { "  flag", "uru.vault.ref.flag",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_masklen,
    { " masklen", "uru.vault.node.masklen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_mask1,
    { " mask1", "uru.vault.node.mask1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_mask2,
    { " mask2", "uru.vault.node.mask2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_index,
    { "  idx", "uru.vault.node.nodeid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_type,
    { "  type", "uru.vault.node.type",
      FT_UINT8, BASE_DEC, VALS(vnodetypes), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_perm,
    { "  permissions", "uru.vault.node.perm",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_owner,
    { "  owner", "uru.vault.node.owner",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_unk1,				/* == Alcugs */
    { "  unk1", "uru.vault.node.unk1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_ts,
    { "  Timestamp", "uru.vault.node.ts",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_sec,
    { "  Timestamp (sec)", "uru.vault.node.sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_usec,
    { "  Timestamp (microsec)", "uru.vault.node.usec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_id1,
    { "  id1", "uru.vault.node.id1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_ts2,
    { "  Timestamp", "uru.vault.node.ts2",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_sec2,
    { "  Timestamp (sec)", "uru.vault.node.sec2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_usec2,
    { "  Timestamp (microsec)", "uru.vault.node.usec2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_ts3,
    { "  Timestamp", "uru.vault.node.ts3",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_sec3,
    { "  Timestamp (sec)", "uru.vault.node.sec3",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_usec3,
    { "  Timestamp (microsec)", "uru.vault.node.usec3",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_agename,
    { "  agename", "uru.vault.node.agename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_hexguid,
    { "  GUID", "uru.vault.node.hexguid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_ftype,
    { "  Folder type/torans", "uru.vault.node.ftype",
      FT_UINT32, BASE_DEC, VALS(vfoldertypes), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_dist,
    { "  dist", "uru.vault.node.dist",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_elev,
    { "  elev", "uru.vault.node.elev",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_unk5,				/* == Alcugs */
    { "  unk5", "uru.vault.node.unk5",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_id2,
    { "  id2", "uru.vault.node.id2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_unk7,				/* == Alcugs */
    { "  unk7", "uru.vault.node.unk7",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_unk8,				/* == Alcugs */
    { "  unk8", "uru.vault.node.unk8",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_unk9,				/* == Alcugs */
    { "  unk9", "uru.vault.node.unk9",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_entryname,
    { "  Entry name", "uru.vault.node.entryname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_subentry,
    { "  subentry", "uru.vault.node.subentry",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_ownername,
    { "  Owner name", "uru.vault.node.ownername",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_guid,
    { "  GUID", "uru.vault.node.guid",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_str1,
    { "  str1", "uru.vault.str1.",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_str2,
    { "  str2", "uru.vault.node.str2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_avname,
    { "  Avatar", "uru.vault.node.avname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_uid,
    { "  UID", "uru.vault.node.uid",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_entry,
    { "  entry", "uru.vault.node.entry",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_entry2,
    { "  entry2", "uru.vault.node.entry2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_dsize,
    { "  data size", "uru.vault.node.dsize",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_data,
    { "  Data", "uru.vault.node.data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_d2size,
    { "  data2 size", "uru.vault.node.d2size",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_data2,
    { "  Data2", "uru.vault.node.data2",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_blob1,
    { "  blob1", "uru.vault.node.blob1",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_node_blob2,
    { "  blob2", "uru.vault.node.blob2",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ctx16,
    { "Ctx", "uru.vault.ctx",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_ctx,
    { "Ctx", "uru.vault.ctx",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_res,
    { "Res", "uru.vault.res",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_mgr,
    { "Manager", "uru.vault.mgr",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_vn,
    { "Vn", "uru.vault.vn",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgCreatePlayer */
  { &hf_uru_create_avname,
    { "Avatar name", "uru.create.avname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_create_gender,
    { "Gender", "uru.create.gender",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_create_fname,
    { "Friend name", "uru.create.fname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_create_passkey,
    { "Passkey", "uru.create.passkey",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_create_unk1, /* Alcugs thinks this is 2 bytes */
    { "Unknown 1", "uru.create.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgPlayerCreated */
  { &hf_uru_created_resp,
    { "Response", "uru.created.resp",
      FT_UINT8, BASE_HEX, VALS(createresponses), 0x0,
      "", HFILL }
  },
  /* NetMsgDeletePlayer */
  { &hf_uru_delete_unk1,
    { "Unknown 1", "uru.delete.unk1",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },

  /* NetMsgGameMessage */
  { &hf_uru_gamemsg_uncsize,
    { "Uncompressed size", "uru.gamemsg.uncsize",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_cflag,
    { "Compression", "uru.gamemsg.cflag",
      FT_UINT8, BASE_HEX, VALS(compflags), 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_msglen,
    { "Message length", "uru.gamemsg.msglen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_type,
    { "Type", "uru.gamemsg.type",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_subobjct,
    { "Subobject count", "uru.gamemsg.subobjct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_unk2,
    { "Unknown 2", "uru.gamemsg.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_unk3,
    { "Unknown 3", "uru.gamemsg.unk3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_flags,
    { "Message flags", "uru.gamemsg.flags",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_unk6,
    { "Unknown 6", "uru.kimsg.unk6",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_sender,
    { "Sender", "uru.kimsg.sender",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_senderKI,
    { "Sender KI", "uru.kimsg.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_msg,
    { "Message", "uru.kimsg.msg",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_chatflags,
    { "Flags", "uru.kimsg.flags",
      FT_UINT16, BASE_HEX, NULL, 0,
      "", HFILL }
  },
  { &hf_uru_kimsg_private,
    { "Private", "uru.kimsg.private",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatPrivate,
      "", HFILL }
  },
  { &hf_uru_kimsg_admin,
    { "Admin", "uru.kimsg.admin",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatAdmin,
      "", HFILL }
  },
  { &hf_uru_kimsg_flag04,
    { "Unknown", "uru.kimsg.flag04",
      FT_BOOLEAN, 16, TFS(&yes_no), 0x0004,
      "", HFILL }
  },
  { &hf_uru_kimsg_interage,
    { "InterAge", "uru.kimsg.interage",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatInterAge,
      "", HFILL }
  },
  { &hf_uru_kimsg_status,
    { "StatusMsg", "uru.kimsg.status",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatStatusMsg,
      "", HFILL }
  },
  { &hf_uru_kimsg_neighbors,
    { "NeighborsMsg", "uru.kimsg.neighbors",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatNeighborsMsg,
      "", HFILL }
  },
  { &hf_uru_kimsg_translate,
    { "Translate", "uru.kimsg.translate",
      FT_BOOLEAN, 16, TFS(&yes_no), kRTChatTranslate,
      "", HFILL }
  },
  { &hf_uru_kimsg_flag80,
    { "Unknown", "uru.kimsg.flag80",
      FT_BOOLEAN, 16, TFS(&yes_no), 0x0080,
      "", HFILL }
  },
  { &hf_uru_kimsg_channel,
    { "Channel", "uru.kimsg.channel",
      FT_UINT16, BASE_DEC, NULL, 0xff00,
      "", HFILL }
  },
  { &hf_uru_kimsg_unk7,
    { "KI unknown 7", "uru.kimsg.unk7",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_unk8,
    { "KI unknown 8", "uru.kimsg.unk8",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_kimsg_unk9,
    { "KI unknown 9", "uru.kimsg.unk9",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk2,
    { "KI unknown 2", "uru.linkmsg.unk2",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_msglen,
    { "Message length", "uru.linkmsg.msglen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_str,
    { "Unknown string", "uru.linkmsg.str",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk4,
    { "Link unknown 4", "uru.linkmsg.unk4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk5,
    { "Link unknown 5", "uru.linkmsg.unk5",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk6,
    { "Link unknown 6", "uru.linkmsg.unk6",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk7,
    { "Link unknown 7", "uru.linkmsg.unk7",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk8,
    { "Link unknown 8", "uru.linkmsg.unk8",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_unk9,
    { "Link unknown 9", "uru.linkmsg.unk9",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkmsg_reqki,
    { "Requester", "uru.linkmsg.reqki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_unk2,
    { "Notify unknown 2", "uru.notify.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_state,
    { "Notify state", "uru.notify.state",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_unk4,
    { "Notify unknown 4", "uru.notify.unk4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_eventct,
    { "Event count", "uru.notify.eventct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_event0,
    { "Event type (event[0])", "uru.notify.event0",
      FT_UINT32, BASE_DEC, VALS(eventtypes), 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_objexists,
    { "  Exists", "uru.notify.exists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_obj,
    { "  Object", "uru.notify.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_offer_event2,
    { "  event[2]", "uru.notify.offer.event2",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_offer_event3,
    { "  event[3]", "uru.notify.offer.event3",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_multistg_num,
    { "  Stage number (event[1])", "uru.notify.multi.number",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_multistg_event,
    { "  Multistage Event (event[2])", "uru.notify.multi.event",
      FT_UINT32, BASE_DEC, VALS(multistgs), 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_picked_event3,
    { "  event[3]", "uru.notify.picked.event3",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_picked_x,
    { "  x?", "uru.notify.picked.x",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_picked_y,
    { "  y?", "uru.notify.picked.y",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_picked_z,
    { "  z?", "uru.notify.picked.z",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_coll_event1,
    { "  event[1]", "uru.notify.coll.event1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_contain_ex,
    { "  extra thing", "uru.notify.contain.ex",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_contain_event2s,
    { "  event[2]", "uru.notify.contain.event2s",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_contain_event2,
    { "  event[2]", "uru.notify.contain.event2",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_var_var,
    { "  Variable", "uru.notify.var.var",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_var_type,
    { "  event[2]", "uru.notify.var.event2",
      FT_UINT32, BASE_DEC, VALS(notifydatatype), 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_var_event3f,
    { "  event[3]", "uru.notify.var.event3",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_var_event3o,
    { "  event[3]", "uru.notify.var.event3",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_var_event4,
    { "  event[4]", "uru.notify.var.event4",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_respst_state,
    { "  event[1]", "uru.notify.respst.state",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_facing_event3,
    { "  event[3]", "uru.notify.facing.event3",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_facing_event4,
    { "  event[4]", "uru.notify.facing.event4",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_act_event1,
    { "  event[1]", "uru.notify.act.event1",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_act_event2,
    { "  event[2]", "uru.notify.act.event2",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_num13_ki,
    { "  event[1]", "uru.notify.num13.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_notify_num13_event2,
    { "  event[2]", "uru.notify.num13.event2",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_unk1,
    { "Iface unknown 1", "uru.iface.unk1",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_float,
    { "A number?", "uru.iface.float",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_str1,
    { "String 1", "uru.iface.str1",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_str2,
    { "String 2", "uru.iface.str2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_str3,
    { "String 3", "uru.iface.str3",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_objexists,
    { "Exists", "uru.iface.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_iface_obj,
    { "Object", "uru.iface.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_srply_reply,
    { "Reply", "uru.srply.reply",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avstate_flags,
    { "State flags", "uru.avstate.flags",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avstate_fwd,
    { "Forward", "uru.avstate.fwd",
      FT_BOOLEAN, 16, NULL, InputForward,
      "", HFILL }
  },
  { &hf_uru_avstate_back,
    { "Backward", "uru.avstate.back",
      FT_BOOLEAN, 16, NULL, InputBack,
      "", HFILL }
  },
  { &hf_uru_avstate_left,
    { "Turn Left", "uru.avstate.left",
      FT_BOOLEAN, 16, NULL, InputTurnLeft,
      "", HFILL }
  },
  { &hf_uru_avstate_right,
    { "Turn Right", "uru.avstate.right",
      FT_BOOLEAN, 16, NULL, InputTurnRight,
      "", HFILL }
  },
  { &hf_uru_avstate_sidel,
    { "Sidestep Left", "uru.avstate.sidel",
      FT_BOOLEAN, 16, NULL, InputSidestepLeft,
      "", HFILL }
  },
  { &hf_uru_avstate_sider,
    { "Sidestep Right", "uru.avstate.sider",
      FT_BOOLEAN, 16, NULL, InputSidestepRight,
      "", HFILL }
  },
  { &hf_uru_linkeff_unk0,
    { "LinkEffect unknown 0", "uru.linkeff.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_unk1,
    { "LinkEffect unknown 1", "uru.linkeff.unk1",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_objexists,
    { "Exists", "uru.linkeff.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_obj,
    { "Object", "uru.linkeff.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_unk2,
    { "LinkEffect unknown 2", "uru.linkeff.unk2",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_effexists,
    { "Exists", "uru.linkeff.effexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_linkeff_eff,
    { "Effect", "uru.linkeff.eff",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_flags,
    { "Clothing flags", "uru.clothing.flags",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_present,
    { "Item present?", "uru.clothing.present",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_objexists,
    { "Exists", "uru.clothing.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_item,
    { "Clothing item", "uru.clothing.item",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_r,
    { "Red", "uru.clothing.r",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_g,
    { "Green", "uru.clothing.g",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_b,
    { "Blue", "uru.clothing.b",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_o,
    { "Other", "uru.clothing.o",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_flag,
    { "Flag", "uru.clothing.flag",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_clothing_unk3,
    { "Clothing unknown 3", "uru.clothing.unk3",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_msgtype,
    { "Wall message type", "uru.wall.msgtype",
      FT_UINT8, BASE_HEX, VALS(wallmsgs), 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_unk0,
    { "Wall unknown", "uru.wall.unk0",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_sstate,
    { "Wall South state", "uru.wall.sstate",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_nstate,
    { "Wall North state", "uru.wall.nstate",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_bl,
    { "Wall blocker number setting", "uru.wall.bl",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_blct,
    { "Wall blocker count", "uru.wall.blct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_blidx,
    { "Wall blocker index", "uru.wall.blidx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_side,
    { "Wall blocker side", "uru.wall.side",
      FT_BOOLEAN, 8, TFS(&north_south), 0x0,
      "", HFILL }
  },
  { &hf_uru_wall_state,
    { "Wall state", "uru.wall.state",
      FT_UINT8, BASE_HEX, VALS(wallstates), 0x0,
      "", HFILL }
  },
  { &hf_uru_warp_matrix,
    { "Warp matrix", "uru.warp.matrix",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_warp_unk,
    { "Warp unknown", "uru.warp.unk",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subworld_objexists,
    { "Exists", "uru.subworld.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_subworld_obj,
    { "Object", "uru.subworld.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_enable_unk0,
    { "Enable unknown 0", "uru.enable.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_enable_unk1,
    { "Enable unknown 1", "uru.enable.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_enable_unk2,
    { "Enable unknown 2", "uru.enable.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_unk0,
    { "AvSeek unknown 0", "uru.avseek.unk0",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_tox,
    { "To x?", "uru.avseek.tox",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_toy,
    { "To y?", "uru.avseek.toy",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_toz,
    { "To z?", "uru.avseek.toz",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_fmx,
    { "From x?", "uru.avseek.fmx",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_fmy,
    { "From y?", "uru.avseek.fmy",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_fmz,
    { "From z?", "uru.avseek.fmz",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_unk1,
    { "AvSeek unknown 1", "uru.avseek.unk1",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_unk2,
    { "AvSeek unknown 2", "uru.avseek.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avseek_unk3,
    { "AvSeek unknown 3", "uru.avseek.unk3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_unk0,
    { "AvTask unknown 0", "uru.avtask.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_type,
    { "Type", "uru.avtask.type",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_name,
    { "Name", "uru.avtask.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_action,
    { "Action", "uru.avtask.action",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk0,
    { "OneShot unknown 0", "uru.oneshot.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_objexists,
    { "Exists", "uru.oneshot.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_obj,
    { "Object", "uru.oneshot.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk1,
    { "OneShot unknown 1", "uru.oneshot.unk1",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk2,
    { "OneShot unknown 2", "uru.oneshot.unk2",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk3,
    { "OneShot unknown 3", "uru.oneshot.unk3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk4,
    { "OneShot unknown 4", "uru.oneshot.unk4",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_anim,
    { "Animation", "uru.oneshot.anim",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_oneshot_unk5,
    { "OneShot unknown 5", "uru.oneshot.unk5",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk0,
    { "ControlEvent unknown 0", "uru.ctrlevt.unk0",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk1,
    { "ControlEvent unknown 1", "uru.ctrlevt.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk2,
    { "ControlEvent unknown 2", "uru.ctrlevt.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk3,
    { "ControlEvent unknown 3", "uru.ctrlevt.unk3",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk4,
    { "ControlEvent unknown 4", "uru.ctrlevt.unk4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk5,
    { "ControlEvent unknown 5", "uru.ctrlevt.unk5",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_unk6,
    { "ControlEvent unknown 6", "uru.ctrlevt.unk6",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_ctrlevt_cmd,
    { "Command", "uru.ctrlevt.cmd",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_multimod_unk0,
    { "MultistageMod unknown 0", "uru.multimod.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_multimod_unk1,
    { "MultistageMod unknown 1", "uru.multimod.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_multimod_unk2,
    { "MultistageMod unknown 2", "uru.multimod.unk2",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_multimod_unk3,
    { "MultistageMod unknown 3", "uru.multimod.unk3",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_climb_unk0,
    { "Climb unknown 0", "uru.climb.unk0",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_climb_unk1,
    { "Climb unknown 1", "uru.climb.unk1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_climb_unk2,
    { "Climb unknown 2", "uru.climb.unk2",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_climb_objexists,
    { "Exists", "uru.climb.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_climb_obj,
    { "Climb object", "uru.climb.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_fakelink_destexists,
    { "Exists", "uru.fakelink.destexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_fakelink_dest,
    { "Fakelink destination", "uru.fakelink.dest",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_fakelink_objexists,
    { "Exists", "uru.fakelink.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_fakelink_obj,
    { "Fakelink avatar", "uru.fakelink.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_brain_unk0,
    { "BrainGeneric unknown 0", "uru.brain.unk0",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_brain_unk1,
    { "BrainGeneric unknown 1", "uru.brain.unk1",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_brain_unk2,
    { "BrainGeneric unknown 2", "uru.brain.unk2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_brain_unk3,
    { "BrainGeneric unknown 3", "uru.brain.unk3",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_brain_time,
    { "BrainGeneric time?", "uru.brain.time",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unk0,
    { "Share unknown 0", "uru.share.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_type,
    { "Share type", "uru.share.type",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_share_sharerexists,
    { "Sharer Exists", "uru.share.sharerexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_sharer,
    { "Sharer", "uru.share.sharer",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_shareeexists,
    { "Sharee Exists", "uru.share.shareeexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_sharee,
    { "Sharee", "uru.share.sharee",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unktype,
    { "Share unknown type", "uru.share.unktype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unk1,
    { "Share unknown 1", "uru.share.unk1",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unkflag,
    { " Share unknown flag", "uru.share.unkflag",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_avmgrexists,
    { " Share AvatarMgr exists", "uru.share.avmgrexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_avmgr,
    { " Share AvatarMgr", "uru.share.avmgr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_bytes,
    { " Share stuff", "uru.share.stuff",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_stagect,
    { " Share stage count", "uru.share.stagect",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_stagetype,
    { "  Share stage type", "uru.share.stagetype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_share_stagename,
    { "  Share stage name", "uru.share.stagename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_stagebytes,
    { "  Share stage stuff", "uru.share.stagestuff",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_fromki,
    { " Share from KI", "uru.share.fromki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_stageunk,
    { " Share stage unknown", "uru.share.stageunk",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unk2,
    { " Share unknown 2", "uru.share.unk2",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_keyexists,
    { " Share key exists", "uru.share.keyexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_key,
    { " Share key", "uru.share.key",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_netmgrexists,
    { "Share NetMgr exists", "uru.share.netmgrexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_netmgr,
    { "Share NetMgr", "uru.share.netmgr",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_str0,
    { "Share string 0", "uru.share.str0",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_strc,
    { "Share string c", "uru.share.strc",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unk4,
    { "Share unknown 4", "uru.share.unk4",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_ki,
    { "Share KI", "uru.share.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_share_unk5,
    { "Share unknown 5", "uru.share.unk5",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_braintype,
    { "Brain type", "uru.avtask.braintype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_brainstage,
    { "Brain stage", "uru.avtask.brainstage",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_brainunk1,
    { "Brain unknown 1", "uru.avtask.brainunk1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_braintime1,
    { "Stage fadeIn?", "uru.avtask.braintime1",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_braintime2,
    { "Stage fadeOut?", "uru.avtask.braintime2",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_stagect,
    { "Stage count", "uru.avtask.stagect",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_stagetype,
    { "Stage type", "uru.avtask.stagetype",
      FT_UINT16, BASE_HEX, VALS(typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_stagename,
    { "Stage name", "uru.avtask.stagetype",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_bytes,
    { "Unknown", "uru.avtask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avtask_brainunk0,
    { "Brain unknown 0", "uru.avtask.brainunk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_physical_vx,
    { "x", "uru.physical.vx",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_physical_vy,
    { "y", "uru.physical.vy",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_physical_vz,
    { "z", "uru.physical.vz",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_physical_v,
    { "Vector", "uru.physical.v",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avenable_unk0,
    { "Enable", "uru.avenable.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_avenable_en,
    { "Enable", "uru.avenable.en",
      FT_BOOLEAN, 16, TFS(&yes_no), 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_objexists,
    { "Particle object exists", "uru.particle.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_obj,
    { "Particle object", "uru.particle.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_count,
    { "Particle count", "uru.particle.ct",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_killnum,
    { "Particle number to kill", "uru.particle.killnum",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_killtime,
    { "Particle kill time left", "uru.particle.killtime",
      FT_FLOAT, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_particle_killflags,
    { "Particle kill flags", "uru.particle.killflags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_gamemsg_endthing,
    { "End thing", "uru.gamemsg.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgGameMessageDirected */
  { &hf_uru_directed_recipct,
    { "Recipients", "uru.directed.recipct",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_directed_recip,
    { "  ", "uru.directed.recip",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgGetPublicAgeList */
  { &hf_uru_pubage_name,
    { "Age name", "uru.pubage.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgPublicAgeList */
  { &hf_uru_pubage_ct,
    { "Instance count", "uru.pubage.ct",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pubage_popct,
    { "Population count", "uru.pubage.popct",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_pubage_pop,
    { "Population", "uru.pubage.pop",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgPython */
  { &hf_uru_python_contents,
    { "Contents", "uru.python.contents",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_python_objexists,
    { "Exists", "uru.python.objexists",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_python_obj,
    { "Key", "uru.python.obj",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  /* NetMsgRelevanceRegions */
  { &hf_uru_relevance_len1,
    { "Length 1?", "uru.relevance.len1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_relevance_occupied,
    { "Occupied", "uru.relevance.occupied",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_ferry,
    { "Ferry", "uru.relevance.occupied.ferry",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegFerry,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_greatstair,
    { "Great Stair", "uru.relevance.occupied.greatstair",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegGreatStair,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_kahlopub,
    { "Kahlo Pub", "uru.relevance.occupied.kahlopub",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegKahloPub,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_courtyard,
    { "Courtyard", "uru.relevance.occupied.courtyard",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCourtyard,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_takotahalley,
    { "Takotah Alley", "uru.relevance.occupied.takotahalley",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegDakotahAlley,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_museumalley,
    { "Museum Alley", "uru.relevance.occupied.museumalley",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegMuseumAlley,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_palace01,
    { "Palace01", "uru.relevance.occupied.palace01",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegPalace01,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_palace02,
    { "Palace02", "uru.relevance.occupied.palace02",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegPalace02,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_tjunction,
    { "Cave T Junction", "uru.relevance.occupied.tjunction",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCaveTJunction,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_canyon,
    { "Canyon", "uru.relevance.occupied.canyon",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCanyon,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_concerthall,
    { "Concert Hall", "uru.relevance.occupied.concerthall",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegConcertHall,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_bridgestairs,
    { "Bridge & Stairs", "uru.relevance.occupied.bridgestairs",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegBridgeStairs,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_librarywalk,
    { "Library Walk", "uru.relevance.occupied.librarywalk",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryWalk,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_librarystairs,
    { "Library Stairs", "uru.relevance.occupied.librarystairs",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryStairs,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_libraryext,
    { "Library Ext", "uru.relevance.occupied.libraryext",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryExt,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_kadishgallery,
    { "Kadish Gallery", "uru.relevance.occupied.kadishgallery",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegKadishGallery,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_mystery,
    { "Mystery", "uru.relevance.occupied.mystery",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegDefaultMaybe,
      "", HFILL }
  },
  { &hf_uru_relevance_occ_unknown,
    { "Unknown", "uru.relevance.occupied.unknown",
      FT_UINT32, BASE_HEX, NULL, 0xfffe0000,
      "", HFILL }
  },
  { &hf_uru_relevance_len2,
    { "Length 2?", "uru.relevance.len2",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting,
    { "Interesting", "uru.relevance.interesting",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_ferry,
    { "Ferry", "uru.relevance.interesting.ferry",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegFerry,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_greatstair,
    { "Great Stair", "uru.relevance.interesting.greatstair",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegGreatStair,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_kahlopub,
    { "Kahlo Pub", "uru.relevance.interesting.kahlopub",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegKahloPub,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_courtyard,
    { "Courtyard", "uru.relevance.interesting.courtyard",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCourtyard,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_takotahalley,
    { "Takotah Alley", "uru.relevance.interesting.takotahalley",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegDakotahAlley,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_museumalley,
    { "Museum Alley", "uru.relevance.interesting.museumalley",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegMuseumAlley,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_palace01,
    { "Palace01", "uru.relevance.interesting.palace01",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegPalace01,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_palace02,
    { "Palace02", "uru.relevance.interesting.palace02",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegPalace02,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_tjunction,
    { "Cave T Junction", "uru.relevance.interesting.tjunction",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCaveTJunction,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_canyon,
    { "Canyon", "uru.relevance.interesting.canyon",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegCanyon,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_concerthall,
    { "Concert Hall", "uru.relevance.interesting.concerthall",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegConcertHall,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_bridgestairs,
    { "Bridge & Stairs", "uru.relevance.interesting.bridgestairs",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegBridgeStairs,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_librarywalk,
    { "Library Walk", "uru.relevance.interesting.librarywalk",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryWalk,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_librarystairs,
    { "Library Stairs", "uru.relevance.interesting.librarystairs",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryStairs,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_libraryext,
    { "Library Ext", "uru.relevance.interesting.libraryext",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegLibraryExt,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_kadishgallery,
    { "Kadish Gallery", "uru.relevance.interesting.kadishgallery",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegKadishGallery,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_mystery,
    { "Mystery", "uru.relevance.interesting.mystery",
      FT_BOOLEAN, 32, TFS(&yes_no), cRelRegDefaultMaybe,
      "", HFILL }
  },
  { &hf_uru_relevance_interesting_unknown,
    { "Unknown", "uru.relevance.interesting.unknown",
      FT_UINT32, BASE_HEX, NULL, 0xfffe0000,
      "", HFILL }
  },

  /* special cases */
  { &hf_uru_cmd_uu,
    { "Command", "uru.cmd",
      FT_UINT16, BASE_HEX, VALS(uu_typecodes), 0x0,
      "Which kind of NetMsg this is", HFILL }
  },
  { &hf_uru_cmd_pots,
    { "Command", "uru.cmd",
      FT_UINT16, BASE_HEX, VALS(pots_typecodes), 0x0,
      "Which kind of NetMsg this is", HFILL }
  },
  { &hf_uru_vault_dtype_uu,
    { "Data type", "uru.vault.dtype",
      FT_UINT16, BASE_HEX, VALS(uu_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_vault_dtype_pots,
    { "Data type", "uru.vault.dtype",
      FT_UINT16, BASE_HEX, VALS(pots_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_uru_ischat,
    { "Chat message", "uru.chat",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Set if this is a chat message (convenience field)", HFILL }
  },

  /* for fragment reassembly */
  {&hf_uru_fragments,
   {"Message fragments", "uru.fragments",
    FT_NONE, BASE_NONE, NULL, 0x00,	NULL, HFILL } },
  {&hf_uru_fragment,
   {"Message fragment", "uru.fragment",
    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
  {&hf_uru_fragment_overlap,
   {"Message fragment overlap", "uru.fragment.overlap",
    FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
  {&hf_uru_fragment_overlap_conflicts,
   {"Message fragment overlapping with conflicting data",
    "uru.fragment.overlap.conflicts",
    FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
  {&hf_uru_fragment_multiple_tails,
   {"Message has multiple tail fragments",
    "uru.fragment.multiple_tails", 
    FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
  {&hf_uru_fragment_too_long_fragment,
   {"Message fragment too long", "uru.fragment.too_long_fragment",
    FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
  {&hf_uru_fragment_error,
   {"Message defragmentation error", "uru.fragment.error",
    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
#ifdef HAVE_FRAGMENT_COUNT
  {&hf_uru_fragment_count,
   {"Message fragment count", "uru.fragment.count",
    FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
#endif
#ifdef HAVE_REASSEMBLED_LENGTH
  {&hf_uru_reassembled_length,
   {"Reassembled length", "uru.reassembled.length",
    FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
#endif
  {&hf_uru_reassembled_in,
   {"Reassembled in", "uru.reassembled.in",
    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } }
};
