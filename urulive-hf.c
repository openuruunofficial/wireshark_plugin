/* 
   Please note, this file is meant to #included, one time only, in the
   main packet-uru.c file.  It should not be compiled standalone.
   This file exists to preserve my sanity while writing the dissectors,
   because I spend a lot of time changing the contents of the header
   fields around (since I am not working with a documented protocol and
   cannot just list them up front).
*/

/*
 * urulive-hf.c
 * The hf_register_info array for the Uru Live protocol.
 *
 * Copyright (C) 2006-2010  a'moaca' and cjkelly1
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

/* "transport layer" equivalent (overall message formatting) */
static int hf_urulive_msgtype_client_v1 = -1;
static int hf_urulive_msgtype_server_v1 = -1;
static int hf_urulive_msgtype_auth_client8 = -1;
static int hf_urulive_msgtype_auth_server8 = -1;
static int hf_urulive_msgtype_gate_client = -1;
static int hf_urulive_msgtype_gate_server = -1;
static int hf_urulive_msgtype_auth_client = -1;
static int hf_urulive_msgtype_auth_server = -1;
static int hf_urulive_msgtype_game_client = -1;
static int hf_urulive_msgtype_game_server = -1;
static int hf_urulive_cmd = -1;
static int hf_urulive_cmd2 = -1;
static int hf_urulive_msglen = -1;
static int hf_urulive_encrypted = -1;

/* this shows up in a lot of messages */
static int hf_urulive_result = -1;

/* Live message-specific fields */
static int hf_urulive_nego_type = -1;
static int hf_urulive_nego_len = -1;
static int hf_urulive_nego_unk0 = -1;
static int hf_urulive_nego_ver = -1;
static int hf_urulive_nego_unk32 = -1;
static int hf_urulive_nego_release = -1;
static int hf_urulive_nego_idstring = -1;
static int hf_urulive_nego_datalen = -1;
static int hf_urulive_nego_data = -1;
static int hf_urulive_nego_nonce = -1;
static int hf_urulive_nego_reply = -1;
static int hf_urulive_reqid = -1;
static int hf_urulive_register_ver = -1;
static int hf_urulive_register_reply = -1;
static int hf_urulive_ping_id = -1;
static int hf_urulive_ping_unk1 = -1;
static int hf_urulive_ping_unk2 = -1;
static int hf_urulive_gate_unk0 = -1;
static int hf_urulive_gate_addr = -1;
static int hf_urulive_addr_ip = -1;
static int hf_urulive_addr_uuid = -1;
static int hf_urulive_age_fname = -1;
static int hf_urulive_age_UUID = -1;
static int hf_urulive_age_unk1 = -1;
static int hf_urulive_age_id = -1;
static int hf_urulive_age_nodeid = -1;
static int hf_urulive_age_addr = -1;
static int hf_urulive_age_iname = -1;
static int hf_urulive_age_uname = -1;
static int hf_urulive_age_dname = -1;
static int hf_urulive_age_parentid = -1;
static int hf_urulive_age_mgr = -1;
static int hf_urulive_age_info = -1;
static int hf_urulive_age_inum = -1;
static int hf_urulive_age_public = -1;
static int hf_urulive_age_public32 = -1;
static int hf_urulive_pubage_unk0 = -1;
static int hf_urulive_pubage_ct = -1;
static int hf_urulive_pubage_unk1 = -1;
static int hf_urulive_pubage_owners = -1;
static int hf_urulive_pubage_pop = -1;
static int hf_urulive_login_unk0 = -1;
static int hf_urulive_login_name = -1;
static int hf_urulive_login_hash = -1;
static int hf_urulive_login_token = -1;
static int hf_urulive_login_os = -1;
static int hf_urulive_login_acct = -1;
static int hf_urulive_login_unk8 = -1;
static int hf_urulive_login_flags = -1;
static int hf_urulive_login_key = -1;
static int hf_urulive_plist_ki = -1;
static int hf_urulive_plist_name = -1;
static int hf_urulive_plist_gender = -1;
static int hf_urulive_plist_type = -1;
static int hf_urulive_file_unk0 = -1;
static int hf_urulive_file_list_dir = -1;	/* auth */
static int hf_urulive_file_list_suffix = -1;	/* auth */
static int hf_urulive_file_list_len = -1;	/* auth */
static int hf_urulive_file_list_file = -1;	/* auth */
static int hf_urulive_file_list_fname = -1;	/* auth */
static int hf_urulive_file_list_flen = -1;	/* auth */
static int hf_urulive_file_get_file = -1;	/* auth */
static int hf_urulive_file_get_len = -1;	/* auth */
static int hf_urulive_file_get_offset = -1;	/* auth */
static int hf_urulive_file_get_thislen = -1;	/* auth */
static int hf_urulive_file_get_data = -1;	/* auth */
static int hf_urulive_file_msglen = -1;
static int hf_urulive_file_trans = -1;
static int hf_urulive_file_unknum = -1;
static int hf_urulive_file_mname = -1;
static int hf_urulive_file_fname = -1;
static int hf_urulive_file_buf = -1;
static int hf_urulive_file_mct = -1;
static int hf_urulive_file_mlen = -1;
static int hf_urulive_file_mfile = -1;
static int hf_urulive_file_mpath = -1;
static int hf_urulive_file_muncsum = -1;
static int hf_urulive_file_mcsum = -1;
static int hf_urulive_file_munclen = -1;
static int hf_urulive_file_mclen = -1;
static int hf_urulive_file_mterm = -1;
static int hf_urulive_file_mflags = -1;
static int hf_urulive_file_mflags_sc = -1;
static int hf_urulive_file_mflags_of = -1;
static int hf_urulive_file_mflags_sf = -1;
static int hf_urulive_file_flen = -1;
static int hf_urulive_file_thislen = -1;
static int hf_urulive_file_data = -1;
static int hf_urulive_vault_globalreqid = -1;
static int hf_urulive_vault_player = -1;
static int hf_urulive_vault_nodeid = -1;
static int hf_urulive_vault_unk0 = -1;
static int hf_urulive_vault_itemct = -1;
static int hf_urulive_vault_ref = -1;
static int hf_urulive_vault_len = -1;
static int hf_urulive_vault_parent = -1;
static int hf_urulive_vault_child = -1;
static int hf_urulive_vault_owner = -1;
static int hf_urulive_vault_createtime = -1;
static int hf_urulive_vault_modifytime = -1;
static int hf_urulive_vault_createagename = -1;
static int hf_urulive_vault_createageuuid = -1;
static int hf_urulive_vault_creatoracctid = -1;
static int hf_urulive_vault_creatorid = -1;
static int hf_urulive_vault_nodetype = -1;
static int hf_urulive_vault_int32_1 = -1;
static int hf_urulive_vault_int32_2 = -1;
static int hf_urulive_vault_int32_3 = -1;
static int hf_urulive_vault_int32_4 = -1;
static int hf_urulive_vault_uint32_1 = -1;
static int hf_urulive_vault_uint32_2 = -1;
static int hf_urulive_vault_uint32_3 = -1;
static int hf_urulive_vault_uint32_4 = -1;
static int hf_urulive_vault_uuid_1 = -1;
static int hf_urulive_vault_uuid_2 = -1;
static int hf_urulive_vault_uuid_3 = -1;
static int hf_urulive_vault_uuid_4 = -1;
static int hf_urulive_vault_string64_1 = -1;
static int hf_urulive_vault_string64_2 = -1;
static int hf_urulive_vault_string64_3 = -1;
static int hf_urulive_vault_string64_4 = -1;
static int hf_urulive_vault_string64_5 = -1;
static int hf_urulive_vault_string64_6 = -1;
static int hf_urulive_vault_istring64_1 = -1;
static int hf_urulive_vault_istring64_2 = -1;
static int hf_urulive_vault_text_1 = -1;
static int hf_urulive_vault_text_2 = -1;
static int hf_urulive_vault_blob_1 = -1;
static int hf_urulive_vault_blob_2 = -1;
static int hf_urulive_vault_foldertype = -1;
static int hf_urulive_vault_agename = -1;
static int hf_urulive_vault_online = -1;
static int hf_urulive_vault_acct = -1;
static int hf_urulive_vault_ageUUID = -1;
static int hf_urulive_vault_parentUUID = -1;
static int hf_urulive_vault_age_fname = -1;
static int hf_urulive_vault_name = -1;
static int hf_urulive_vault_type = -1;
static int hf_urulive_vault_value = -1;
static int hf_urulive_vault_imgexists = -1;
static int hf_urulive_vault_imagename = -1;
static int hf_urulive_vault_imagelen = -1;
static int hf_urulive_vault_image = -1;
static int hf_urulive_vault_linkpoint = -1;
static int hf_urulive_vault_volatile = -1;
static int hf_urulive_create_name = -1;
static int hf_urulive_create_gender = -1;
static int hf_urulive_create_code = -1;
static int hf_urulive_log_python = -1;
static int hf_urulive_score_holder = -1;
static int hf_urulive_score_name = -1;
static int hf_urulive_score_unk1 = -1;
static int hf_urulive_score_mlen = -1;
static int hf_urulive_score_id = -1;
static int hf_urulive_score_ts = -1;
static int hf_urulive_score_type = -1;
static int hf_urulive_score_value = -1;
static int hf_urulive_score_add = -1;
static int hf_urulive_score_dest = -1;
static int hf_urulive_gamemgr_msgtype = -1;
static int hf_urulive_gamemgr_reqid = -1;
static int hf_urulive_gamemgr_gameid = -1;
static int hf_urulive_gamemgr_len = -1;
static int hf_urulive_gamemgr_clientid = -1;
static int hf_urulive_gamemgr_unk0 = -1;
static int hf_urulive_gamemgr_uuid = -1; /* transmitted as part of setup */
static int hf_urulive_gamemgr_idresult = -1; /* transmitted as part of setup */
static int hf_urulive_gamemgr_gametype = -1;
static int hf_urulive_gamemgr_extra = -1;
static int hf_urulive_gamemgr_spiralmsg = -1;
static int hf_urulive_gamemgr_clispiralmsg = -1;
static int hf_urulive_gamemgr_heekmsg = -1;
static int hf_urulive_gamemgr_cliheekmsg = -1;
static int hf_urulive_gamemgr_markermsg = -1;
static int hf_urulive_gamemgr_climarkermsg = -1;
static int hf_urulive_gamemgr_gameclimsg = -1;
static int hf_urulive_gamemgr_template = -1;
static int hf_urulive_gamemgr_buf = -1 ;
static int hf_urulive_gamemgr_name = -1;
static int hf_urulive_gamemgr_team = -1;
static int hf_urulive_gamemgr_markerposx = -1;
static int hf_urulive_gamemgr_markerposy = -1;
static int hf_urulive_gamemgr_markerposz = -1;
static int hf_urulive_gamemgr_markernum = -1;
static int hf_urulive_gamemgr_markerdel = -1;
static int hf_urulive_gamemgr_captured = -1;
static int hf_urulive_gamemgr_gametime = -1;
static int hf_urulive_gamemgr_timelimit = -1;
static int hf_urulive_gamemgr_clothorder = -1;
static int hf_urulive_gamemgr_cloth = -1;
static int hf_urulive_gamemgr_rotate = -1;
static int hf_urulive_gamemgr_varsyncmsg = -1;
static int hf_urulive_gamemgr_clivarsyncmsg = -1;
static int hf_urulive_gamemgr_climbingwallmsg = -1;
static int hf_urulive_gamemgr_position = -1;
static int hf_urulive_gamemgr_ifacestate = -1;
static int hf_urulive_gamemgr_countdown = -1;
static int hf_urulive_gamemgr_rank = -1;
static int hf_urulive_gamemgr_choice = -1;
static int hf_urulive_gamemgr_score = -1;
static int hf_urulive_gamemgr_update = -1;
static int hf_urulive_gamemgr_win = -1;
static int hf_urulive_gamemgr_seq = -1;
static int hf_urulive_gamemgr_light = -1;
static int hf_urulive_gamemgr_state = -1;
static int hf_urulive_gamemgr_id = -1;
static int hf_urulive_gamemgr_value = -1;
static int hf_urulive_gamemgr_playing = -1;
static int hf_urulive_gamemgr_single = -1;
static int hf_urulive_gamemgr_enable = -1;
static int hf_urulive_friend_uuid = -1;
static int hf_urulive_friend_addr = -1;
static int hf_urulive_friend_type = -1;

/* additional fields required for dissecting Live messages in
   code shared with UU: fields with either a different size, or that
   were added into the original messages */
static int hf_urulive_obj_type = -1;
static int hf_urulive_subobj_type = -1;
static int hf_urulive_obj_new = -1;
static int hf_urulive_subobj_new = -1;
static int hf_urulive_gamemsg_type = -1;
static int hf_urulive_loadclone_subtype = -1;
static int hf_urulive_loadclone_subctype = -1;
static int hf_urulive_loadclone_name = -1;
static int hf_urulive_avtask_type = -1;
static int hf_urulive_avtask_braintype = -1;
static int hf_urulive_avtask_stagetype = -1;
static int hf_urulive_groupid_bytes = -1;
static int hf_urulive_kimsg_extra = -1;

static const value_string live_typecodes[] = {
  { 0x8000, "No type" },
  { live_plNetMsgSDLStateBCast, "plNetMsgSDLStateBCast" },
  { live_plNetMsgSDLState, "plNetMsgSDLState" },
  { live_plNetMsgGameMessage, "plNetMsgGameMessage" },
  { live_plNetMsgGameMessageDirected, "plNetMsgGameMessageDirected" },
  { live_plNetMsgVoice, "plNetMsgVoice" },
  { live_plNetMsgLoadClone, "plNetMsgLoadClone" },
  { live_plNetMsgPlayerPage, "plNetMsgPlayerPage" },
  { live_plNetMsgRelevanceRegions, "plNetMsgRelevanceRegions" },
  { live_plNetMsgGroupOwner, "plNetMsgGroupOwner" },
  { live_plNetMsgGameStateRequest, "plNetMsgGameStateRequest" },
  { live_plNetMsgMembersListReq, "plNetMsgMembersListReq" },
  { live_plNetMsgMembersList, "plNetMsgMembersList" },
  { live_plNetMsgMemberUpdate, "plNetMsgMemberUpdate" },
  { live_plNetMsgInitialAgeStateSent, "plNetMsgInitialAgeStateSent" },
  { live_plNetMsgTestAndSet, "plNetMsgTestAndSet" },
  { live_plNetMsgPagingRoom, "plNetMsgPagingRoom" },
  { live_plNetClientMgr, "plNetClientMgr" },
  { live_plAvatarMgr, "plAvatarMgr" },
  { live_plLoadAvatarMsg, "plLoadAvatarMsg" },
  { live_pfKIMsg, "pfKIMsg" },
  { live_plLinkToAgeMsg, "plLinkToAgeMsg" },
  { live_plLinkingMgrMsg, "plLinkingMgrMsg" },
  { live_plNotifyMsg, "plNotifyMsg" },
  { live_plInputIfaceMgrMsg, "plInputIfaceMgrMsg" },
  { live_plSceneObject, "plSceneObject" },
  { live_plAvatarInputStateMsg, "plAvatarInputStateMsg" },
  { live_plArmatureLODMod, "plArmatureLODMod" },
  { live_plPythonFileMod, "plPythonFileMod" },
  { live_plAvBrainGenericMsg, "plAvBrainGenericMsg" },
  { live_plAvSeekMsg, "plAvSeekMsg" },
  { live_plServerReplyMsg, "plServerReplyMsg" },
  { live_plLogicModifier, "plLogicModifier" },
  { live_plResponderModifier, "plResponderModifier" },
  { live_plClothingMsg, "plClothingMsg" },
  { live_plClothingOutfit, "plClothingOutfit" },
  { live_plAvTaskMsg, "plAvTaskMsg" },
  { live_plLinkEffectsMgr, "plLinkEffectsMgr" },
  { live_plLinkEffectsTriggerMsg, "plLinkEffectsTriggerMsg" },
  { live_plEnableMsg, "plEnableMsg" },
  { live_plAnimCmdMsg, "plAnimCmdMsg" },
  { live_plAvAnimTask, "plAvAnimTask" },
  { live_plMultistageBehMod, "plMultistageBehMod" },
  { live_plSittingModifier, "plSittingModifier" },
  { live_plPseudoLinkEffectMsg, "plPseudoLinkEffectMsg" },
  { live_plWarpMsg, "plWarpMsg" },
  { live_plSubWorldMsg, "plSubWorldMsg" },
  { live_plSubworldRegionDetector, "plSubworldRegionDetector" },
  { live_plSimulationMgr, "plSimulationMgr" },
  { live_plAvTaskBrain, "plAvTaskBrain" },
  { live_plAvBrainGeneric, "plAvBrainGeneric" },
  { live_plAvOneShotMsg, "plAvOneShotMsg" },
  { live_plClient, "plClient" },
  { live_pfMarkerMgr, "pfMarkerMgr" },
  { live_plLayerAnimation, "plLayerAnimation" },
  { live_plATCAnim, "plATCAnim" },
  { live_plArmatureMod, "plArmatureMod" },
  { live_plAvLadderMod, "plAvLadderMod" },
  { live_plClothingItem, "plClothingItem" },
  { live_plCoopCoordinator, "plCoopCoordinator" },
  { live_plAvCoopMsg, "plAvCoopMsg" },
  { live_plAvBrainCoop, "plAvBrainCoop" },
  { live_plControlEventMsg, "plControlEventMsg" },
  { live_plMultistageModMsg, "plMultistageModMsg" },
  { live_plSharedMesh, "plSharedMesh" },
  { live_plAnimStage, "plAnimStage" },
  { live_plAvOneShotLinkTask, "plAvOneShotLinkTask" },
  { live_plVaultNodeRef, "plVaultNodeRef" },
  { live_plVaultNode, "plVaultNode" },
  { live_plNPCSpawnMod, "plNPCSpawnMod" },
  { live_plSetNetGroupIDMsg, "plSetNetGroupIDMsg" },
  { live_plShiftMassMsg, "plShiftMassMsg" },
  { live_plTorqueMsg, "plTorqueMsg" },
  { live_plImpulseMsg, "plImpulseMsg" },
  { live_plOffsetImpulseMsg, "plOffsetImpulseMsg" },
  { live_plAngularImpulseMsg, "plAngularImpulseMsg" },
  { live_plForceMsg, "plForceMsg" },
  { live_plDampMsg, "plDampMsg" },
  { live_plOffsetForceMsg, "plOffsetForceMsg" },
  { live_plCreatableGenericValue, "plCreatableGenericValue" },
  { live_plCreatableStream, "plCreatableStream" },
  { live_plAgeLinkStruct, "plAgeLinkStruct" },
  { live_plLoadCloneMsg, "plLoadCloneMsg" },
  { live_plParticleTransferMsg, "plParticleTransferMsg" },
  { live_plParticleKillMsg, "plParticleKillMsg" },
#ifdef INCLUDE_ALL_TYPES
  /* this is ALL the types, *including* the ones encountered above;
     the reason for this is to help identify things */
  { live_plSceneNode, "plSceneNode" },
  { live_plSceneObject, "plSceneObject" },
  { live_hsKeyedObject, "hsKeyedObject" },
  { live_plBitmap, "plBitmap" },
  { live_plMipmap, "plMipmap" },
  { live_plCubicEnvironmap, "plCubicEnvironmap" },
  { live_plLayer, "plLayer" },
  { live_hsGMaterial, "hsGMaterial" },
  { live_plParticleSystem, "plParticleSystem" },
  { live_plParticleEffect, "plParticleEffect" },
  { live_plParticleCollisionEffectBeat, "plParticleCollisionEffectBeat" },
  { live_plParticleFadeVolumeEffect, "plParticleFadeVolumeEffect" },
  { live_plBoundInterface, "plBoundInterface" },
  { live_plRenderTarget, "plRenderTarget" },
  { live_plCubicRenderTarget, "plCubicRenderTarget" },
  { live_plCubicRenderTargetModifier, "plCubicRenderTargetModifier" },
  { live_plObjInterface, "plObjInterface" },
  { live_plAudioInterface, "plAudioInterface" },
  { live_plAudible, "plAudible" },
  { live_plAudibleNull, "plAudibleNull" },
  { live_plWinAudible, "plWinAudible" },
  { live_plCoordinateInterface, "plCoordinateInterface" },
  { live_plDrawInterface, "plDrawInterface" },
  { live_plDrawable, "plDrawable" },
  { live_plDrawableMesh, "plDrawableMesh" },
  { live_plDrawableIce, "plDrawableIce" },
  { live_plPhysical, "plPhysical" },
  { live_plPhysicalMesh, "plPhysicalMesh" },
  { live_plSimulationInterface, "plSimulationInterface" },
  { live_plCameraModifier, "plCameraModifier" },
  { live_plModifier, "plModifier" },
  { live_plSingleModifier, "plSingleModifier" },
  { live_plSimpleModifier, "plSimpleModifier" },
  { live_pfSecurePreloader, "pfSecurePreloader" },
  { live_UNUSED_plRandomTMModifier, "UNUSED_plRandomTMModifier" },
  { live_plInterestingModifier, "plInterestingModifier" },
  { live_plDetectorModifier, "plDetectorModifier" },
  { live_plSimplePhysicalMesh, "plSimplePhysicalMesh" },
  { live_plCompoundPhysicalMesh, "plCompoundPhysicalMesh" },
  { live_plMultiModifier, "plMultiModifier" },
  { live_plSynchedObject, "plSynchedObject" },
  { live_plSoundBuffer, "plSoundBuffer" },
  { live_UNUSED_plAliasModifier, "UNUSED_plAliasModifier" },
  { live_plPickingDetector, "plPickingDetector" },
  { live_plCollisionDetector, "plCollisionDetector" },
  { live_plLogicModifier, "plLogicModifier" },
  { live_plConditionalObject, "plConditionalObject" },
  { live_plANDConditionalObject, "plANDConditionalObject" },
  { live_plORConditionalObject, "plORConditionalObject" },
  { live_plPickedConditionalObject, "plPickedConditionalObject" },
  { live_plActivatorConditionalObject, "plActivatorConditionalObject" },
  { live_plTimerCallbackManager, "plTimerCallbackManager" },
  { live_plKeyPressConditionalObject, "plKeyPressConditionalObject" },
  { live_plAnimationEventConditionalObject, "plAnimationEventConditionalObject" },
  { live_plControlEventConditionalObject, "plControlEventConditionalObject" },
  { live_plObjectInBoxConditionalObject, "plObjectInBoxConditionalObject" },
  { live_plLocalPlayerInBoxConditionalObject, "plLocalPlayerInBoxConditionalObject" },
  { live_plObjectIntersectPlaneConditionalObject, "plObjectIntersectPlaneConditionalObject" },
  { live_plLocalPlayerIntersectPlaneConditionalObject, "plLocalPlayerIntersectPlaneConditionalObject" },
  { live_plPortalDrawable, "plPortalDrawable" },
  { live_plPortalPhysical, "plPortalPhysical" },
  { live_plSpawnModifier, "plSpawnModifier" },
  { live_plFacingConditionalObject, "plFacingConditionalObject" },
  { live_plPXPhysical, "plPXPhysical" },
  { live_plViewFaceModifier, "plViewFaceModifier" },
  { live_plLayerInterface, "plLayerInterface" },
  { live_plLayerWrapper, "plLayerWrapper" },
  { live_plLayerAnimation, "plLayerAnimation" },
  { live_plLayerDepth, "plLayerDepth" },
  { live_plLayerMovie, "plLayerMovie" },
  { live_plLayerBink, "plLayerBink" },
  { live_plLayerAVI, "plLayerAVI" },
  { live_plSound, "plSound" },
  { live_plWin32Sound, "plWin32Sound" },
  { live_plLayerOr, "plLayerOr" },
  { live_plAudioSystem, "plAudioSystem" },
  { live_plDrawableSpans, "plDrawableSpans" },
  { live_UNUSED_plDrawablePatchSet, "UNUSED_plDrawablePatchSet" },
  { live_plInputManager, "plInputManager" },
  { live_plLogicModBase, "plLogicModBase" },
  { live_plFogEnvironment, "plFogEnvironment" },
  { live_plNetApp, "plNetApp" },
  { live_plNetClientMgr, "plNetClientMgr" },
  { live_pl2WayWinAudible, "pl2WayWinAudible" },
  { live_plLightInfo, "plLightInfo" },
  { live_plDirectionalLightInfo, "plDirectionalLightInfo" },
  { live_plOmniLightInfo, "plOmniLightInfo" },
  { live_plSpotLightInfo, "plSpotLightInfo" },
  { live_plLightSpace, "plLightSpace" },
  { live_plNetClientApp, "plNetClientApp" },
  { live_plNetServerApp, "plNetServerApp" },
  { live_plClient, "plClient" },
  { live_UNUSED_plCompoundTMModifier, "UNUSED_plCompoundTMModifier" },
  { live_plCameraBrain, "plCameraBrain" },
  { live_plCameraBrain_Default, "plCameraBrain_Default" },
  { live_plCameraBrain_Drive, "plCameraBrain_Drive" },
  { live_plCameraBrain_Fixed, "plCameraBrain_Fixed" },
  { live_plCameraBrain_FixedPan, "plCameraBrain_FixedPan" },
  { live_pfGUIClickMapCtrl, "pfGUIClickMapCtrl" },
  { live_plListener, "plListener" },
  { live_plAvatarMod, "plAvatarMod" },
  { live_plAvatarAnim, "plAvatarAnim" },
  { live_plAvatarAnimMgr, "plAvatarAnimMgr" },
  { live_plOccluder, "plOccluder" },
  { live_plMobileOccluder, "plMobileOccluder" },
  { live_plLayerShadowBase, "plLayerShadowBase" },
  { live_plLimitedDirLightInfo, "plLimitedDirLightInfo" },
  { live_plAGAnim, "plAGAnim" },
  { live_plAGModifier, "plAGModifier" },
  { live_plAGMasterMod, "plAGMasterMod" },
  { live_plCameraBrain_Avatar, "plCameraBrain_Avatar" },
  { live_plCameraRegionDetector, "plCameraRegionDetector" },
  { live_plCameraBrain_FP, "plCameraBrain_FP" },
  { live_plLineFollowMod, "plLineFollowMod" },
  { live_plLightModifier, "plLightModifier" },
  { live_plOmniModifier, "plOmniModifier" },
  { live_plSpotModifier, "plSpotModifier" },
  { live_plLtdDirModifier, "plLtdDirModifier" },
  { live_plSeekPointMod, "plSeekPointMod" },
  { live_plOneShotMod, "plOneShotMod" },
  { live_plRandomCommandMod, "plRandomCommandMod" },
  { live_plRandomSoundMod, "plRandomSoundMod" },
  { live_plPostEffectMod, "plPostEffectMod" },
  { live_plObjectInVolumeDetector, "plObjectInVolumeDetector" },
  { live_plResponderModifier, "plResponderModifier" },
  { live_plAxisAnimModifier, "plAxisAnimModifier" },
  { live_plLayerLightBase, "plLayerLightBase" },
  { live_plFollowMod, "plFollowMod" },
  { live_plTransitionMgr, "plTransitionMgr" },
  { live_UNUSED___plInventoryMod, "UNUSED___plInventoryMod" },
  { live_UNUSED___plInventoryObjMod, "UNUSED___plInventoryObjMod" },
  { live_plLinkEffectsMgr, "plLinkEffectsMgr" },
  { live_plWin32StreamingSound, "plWin32StreamingSound" },
  { live_UNUSED___plPythonMod, "UNUSED___plPythonMod" },
  { live_plActivatorActivatorConditionalObject, "plActivatorActivatorConditionalObject" },
  { live_plSoftVolume, "plSoftVolume" },
  { live_plSoftVolumeSimple, "plSoftVolumeSimple" },
  { live_plSoftVolumeComplex, "plSoftVolumeComplex" },
  { live_plSoftVolumeUnion, "plSoftVolumeUnion" },
  { live_plSoftVolumeIntersect, "plSoftVolumeIntersect" },
  { live_plSoftVolumeInvert, "plSoftVolumeInvert" },
  { live_plWin32LinkSound, "plWin32LinkSound" },
  { live_plLayerLinkAnimation, "plLayerLinkAnimation" },
  { live_plArmatureMod, "plArmatureMod" },
  { live_plCameraBrain_Freelook, "plCameraBrain_Freelook" },
  { live_plHavokConstraintsMod, "plHavokConstraintsMod" },
  { live_plHingeConstraintMod, "plHingeConstraintMod" },
  { live_plWheelConstraintMod, "plWheelConstraintMod" },
  { live_plStrongSpringConstraintMod, "plStrongSpringConstraintMod" },
  { live_plArmatureLODMod, "plArmatureLODMod" },
  { live_plWin32StaticSound, "plWin32StaticSound" },
  { live_pfGameGUIMgr, "pfGameGUIMgr" },
  { live_pfGUIDialogMod, "pfGUIDialogMod" },
  { live_plCameraBrain1, "plCameraBrain1" },
  { live_plVirtualCam1, "plVirtualCam1" },
  { live_plCameraModifier1, "plCameraModifier1" },
  { live_plCameraBrain1_Drive, "plCameraBrain1_Drive" },
  { live_plCameraBrain1_POA, "plCameraBrain1_POA" },
  { live_plCameraBrain1_Avatar, "plCameraBrain1_Avatar" },
  { live_plCameraBrain1_Fixed, "plCameraBrain1_Fixed" },
  { live_plCameraBrain1_POAFixed, "plCameraBrain1_POAFixed" },
  { live_pfGUIButtonMod, "pfGUIButtonMod" },
  { live_plPythonFileMod, "plPythonFileMod" },
  { live_pfGUIControlMod, "pfGUIControlMod" },
  { live_plExcludeRegionModifier, "plExcludeRegionModifier" },
  { live_pfGUIDraggableMod, "pfGUIDraggableMod" },
  { live_plVolumeSensorConditionalObject, "plVolumeSensorConditionalObject" },
  { live_plVolActivatorConditionalObject, "plVolActivatorConditionalObject" },
  { live_plMsgForwarder, "plMsgForwarder" },
  { live_plBlower, "plBlower" },
  { live_pfGUIListBoxMod, "pfGUIListBoxMod" },
  { live_pfGUITextBoxMod, "pfGUITextBoxMod" },
  { live_pfGUIEditBoxMod, "pfGUIEditBoxMod" },
  { live_plDynamicTextMap, "plDynamicTextMap" },
  { live_plSittingModifier, "plSittingModifier" },
  { live_pfGUIUpDownPairMod, "pfGUIUpDownPairMod" },
  { live_pfGUIValueCtrl, "pfGUIValueCtrl" },
  { live_pfGUIKnobCtrl, "pfGUIKnobCtrl" },
  { live_plAvLadderMod, "plAvLadderMod" },
  { live_plCameraBrain1_FirstPerson, "plCameraBrain1_FirstPerson" },
  { live_plCloneSpawnModifier, "plCloneSpawnModifier" },
  { live_plClothingItem, "plClothingItem" },
  { live_plClothingOutfit, "plClothingOutfit" },
  { live_plClothingBase, "plClothingBase" },
  { live_plClothingMgr, "plClothingMgr" },
  { live_pfGUIDragBarCtrl, "pfGUIDragBarCtrl" },
  { live_pfGUICheckBoxCtrl, "pfGUICheckBoxCtrl" },
  { live_pfGUIRadioGroupCtrl, "pfGUIRadioGroupCtrl" },
  { live_pfPlayerBookMod, "pfPlayerBookMod" },
  { live_pfGUIDynDisplayCtrl, "pfGUIDynDisplayCtrl" },
  { live_UNUSED_plLayerProject, "UNUSED_plLayerProject" },
  { live_plInputInterfaceMgr, "plInputInterfaceMgr" },
  { live_plRailCameraMod, "plRailCameraMod" },
  { live_plMultistageBehMod, "plMultistageBehMod" },
  { live_plCameraBrain1_Circle, "plCameraBrain1_Circle" },
  { live_plParticleWindEffect, "plParticleWindEffect" },
  { live_plAnimEventModifier, "plAnimEventModifier" },
  { live_plAutoProfile, "plAutoProfile" },
  { live_pfGUISkin, "pfGUISkin" },
  { live_plAVIWriter, "plAVIWriter" },
  { live_plParticleCollisionEffect, "plParticleCollisionEffect" },
  { live_plParticleCollisionEffectDie, "plParticleCollisionEffectDie" },
  { live_plParticleCollisionEffectBounce, "plParticleCollisionEffectBounce" },
  { live_plInterfaceInfoModifier, "plInterfaceInfoModifier" },
  { live_plSharedMesh, "plSharedMesh" },
  { live_plArmatureEffectsMgr, "plArmatureEffectsMgr" },
  { live_pfMarkerMgr, "pfMarkerMgr" },
  { live_plVehicleModifier, "plVehicleModifier" },
  { live_plParticleLocalWind, "plParticleLocalWind" },
  { live_plParticleUniformWind, "plParticleUniformWind" },
  { live_plInstanceDrawInterface, "plInstanceDrawInterface" },
  { live_plShadowMaster, "plShadowMaster" },
  { live_plShadowCaster, "plShadowCaster" },
  { live_plPointShadowMaster, "plPointShadowMaster" },
  { live_plDirectShadowMaster, "plDirectShadowMaster" },
  { live_plSDLModifier, "plSDLModifier" },
  { live_plPhysicalSDLModifier, "plPhysicalSDLModifier" },
  { live_plClothingSDLModifier, "plClothingSDLModifier" },
  { live_plAvatarSDLModifier, "plAvatarSDLModifier" },
  { live_plAGMasterSDLModifier, "plAGMasterSDLModifier" },
  { live_plPythonSDLModifier, "plPythonSDLModifier" },
  { live_plLayerSDLModifier, "plLayerSDLModifier" },
  { live_plAnimTimeConvertSDLModifier, "plAnimTimeConvertSDLModifier" },
  { live_plResponderSDLModifier, "plResponderSDLModifier" },
  { live_plSoundSDLModifier, "plSoundSDLModifier" },
  { live_plResManagerHelper, "plResManagerHelper" },
  { live_plAvatarPhysicalSDLModifier, "plAvatarPhysicalSDLModifier" },
  { live_plArmatureEffect, "plArmatureEffect" },
  { live_plArmatureEffectFootSound, "plArmatureEffectFootSound" },
  { live_plEAXListenerMod, "plEAXListenerMod" },
  { live_plDynaDecalMgr, "plDynaDecalMgr" },
  { live_plObjectInVolumeAndFacingDetector, "plObjectInVolumeAndFacingDetector" },
  { live_plDynaFootMgr, "plDynaFootMgr" },
  { live_plDynaRippleMgr, "plDynaRippleMgr" },
  { live_plDynaBulletMgr, "plDynaBulletMgr" },
  { live_plDecalEnableMod, "plDecalEnableMod" },
  { live_plPrintShape, "plPrintShape" },
  { live_plDynaPuddleMgr, "plDynaPuddleMgr" },
  { live_pfGUIMultiLineEditCtrl, "pfGUIMultiLineEditCtrl" },
  { live_plLayerAnimationBase, "plLayerAnimationBase" },
  { live_plLayerSDLAnimation, "plLayerSDLAnimation" },
  { live_plATCAnim, "plATCAnim" },
  { live_plAgeGlobalAnim, "plAgeGlobalAnim" },
  { live_plSubworldRegionDetector, "plSubworldRegionDetector" },
  { live_plAvatarMgr, "plAvatarMgr" },
  { live_plNPCSpawnMod, "plNPCSpawnMod" },
  { live_plActivePrintShape, "plActivePrintShape" },
  { live_plExcludeRegionSDLModifier, "plExcludeRegionSDLModifier" },
  { live_plLOSDispatch, "plLOSDispatch" },
  { live_plDynaWakeMgr, "plDynaWakeMgr" },
  { live_plSimulationMgr, "plSimulationMgr" },
  { live_plWaveSet7, "plWaveSet7" },
  { live_plPanicLinkRegion, "plPanicLinkRegion" },
  { live_plWin32GroupedSound, "plWin32GroupedSound" },
  { live_plFilterCoordInterface, "plFilterCoordInterface" },
  { live_plStereizer, "plStereizer" },
  { live_plCCRMgr, "plCCRMgr" },
  { live_plCCRSpecialist, "plCCRSpecialist" },
  { live_plCCRSeniorSpecialist, "plCCRSeniorSpecialist" },
  { live_plCCRShiftSupervisor, "plCCRShiftSupervisor" },
  { live_plCCRGameOperator, "plCCRGameOperator" },
  { live_plShader, "plShader" },
  { live_plDynamicEnvMap, "plDynamicEnvMap" },
  { live_plSimpleRegionSensor, "plSimpleRegionSensor" },
  { live_plMorphSequence, "plMorphSequence" },
  { live_plEmoteAnim, "plEmoteAnim" },
  { live_plDynaRippleVSMgr, "plDynaRippleVSMgr" },
  { live_UNUSED_plWaveSet6, "UNUSED_plWaveSet6" },
  { live_pfGUIProgressCtrl, "pfGUIProgressCtrl" },
  { live_plMaintainersMarkerModifier, "plMaintainersMarkerModifier" },
  { live_plMorphSequenceSDLMod, "plMorphSequenceSDLMod" },
  { live_plMorphDataSet, "plMorphDataSet" },
  { live_plHardRegion, "plHardRegion" },
  { live_plHardRegionPlanes, "plHardRegionPlanes" },
  { live_plHardRegionComplex, "plHardRegionComplex" },
  { live_plHardRegionUnion, "plHardRegionUnion" },
  { live_plHardRegionIntersect, "plHardRegionIntersect" },
  { live_plHardRegionInvert, "plHardRegionInvert" },
  { live_plVisRegion, "plVisRegion" },
  { live_plVisMgr, "plVisMgr" },
  { live_plRegionBase, "plRegionBase" },
  { live_pfGUIPopUpMenu, "pfGUIPopUpMenu" },
  { live_pfGUIMenuItem, "pfGUIMenuItem" },
  { live_plCoopCoordinator, "plCoopCoordinator" },
  { live_plFont, "plFont" },
  { live_plFontCache, "plFontCache" },
  { live_plRelevanceRegion, "plRelevanceRegion" },
  { live_plRelevanceMgr, "plRelevanceMgr" },
  { live_pfJournalBook, "pfJournalBook" },
  { live_plLayerTargetContainer, "plLayerTargetContainer" },
  { live_plImageLibMod, "plImageLibMod" },
  { live_plParticleFlockEffect, "plParticleFlockEffect" },
  { live_plParticleSDLMod, "plParticleSDLMod" },
  { live_plAgeLoader, "plAgeLoader" },
  { live_plWaveSetBase, "plWaveSetBase" },
  { live_plPhysicalSndGroup, "plPhysicalSndGroup" },
  { live_pfBookData, "pfBookData" },
  { live_plDynaTorpedoMgr, "plDynaTorpedoMgr" },
  { live_plDynaTorpedoVSMgr, "plDynaTorpedoVSMgr" },
  { live_plClusterGroup, "plClusterGroup" },
  { live_plGameMarkerModifier, "plGameMarkerModifier" },
  { live_plLODMipmap, "plLODMipmap" },
  { live_plSwimDetector, "plSwimDetector" },
  { live_plFadeOpacityMod, "plFadeOpacityMod" },
  { live_plFadeOpacityLay, "plFadeOpacityLay" },
  { live_plDistOpacityMod, "plDistOpacityMod" },
  { live_plArmatureModBase, "plArmatureModBase" },
  { live_plSwimRegionInterface, "plSwimRegionInterface" },
  { live_plSwimCircularCurrentRegion, "plSwimCircularCurrentRegion" },
  { live_plParticleFollowSystemEffect, "plParticleFollowSystemEffect" },
  { live_plSwimStraightCurrentRegion, "plSwimStraightCurrentRegion" },
  { live_pfObjectFlocker, "pfObjectFlocker" },
  { live_plGrassShaderMod, "plGrassShaderMod" },
  { live_plDynamicCamMap, "plDynamicCamMap" },
  { live_plRidingAnimatedPhysicalDetector, "plRidingAnimatedPhysicalDetector" },
  { live_plVolumeSensorConditionalObjectNoArbitration, "plVolumeSensorConditionalObjectNoArbitration" },
  { live_plObjRefMsg, "plObjRefMsg" },
  { live_plNodeRefMsg, "plNodeRefMsg" },
  { live_plMessage, "plMessage" },
  { live_plRefMsg, "plRefMsg" },
  { live_plGenRefMsg, "plGenRefMsg" },
  { live_plTimeMsg, "plTimeMsg" },
  { live_plAnimCmdMsg, "plAnimCmdMsg" },
  { live_plParticleUpdateMsg, "plParticleUpdateMsg" },
  { live_plLayRefMsg, "plLayRefMsg" },
  { live_plMatRefMsg, "plMatRefMsg" },
  { live_plCameraMsg, "plCameraMsg" },
  { live_plInputEventMsg, "plInputEventMsg" },
  { live_plKeyEventMsg, "plKeyEventMsg" },
  { live_plMouseEventMsg, "plMouseEventMsg" },
  { live_plEvalMsg, "plEvalMsg" },
  { live_plTransformMsg, "plTransformMsg" },
  { live_plControlEventMsg, "plControlEventMsg" },
  { live_plVaultCCRNode, "plVaultCCRNode" },
  { live_plLOSRequestMsg, "plLOSRequestMsg" },
  { live_plLOSHitMsg, "plLOSHitMsg" },
  { live_plSingleModMsg, "plSingleModMsg" },
  { live_plMultiModMsg, "plMultiModMsg" },
  { live_plAvatarPhysicsEnableCallbackMsg, "plAvatarPhysicsEnableCallbackMsg" },
  { live_plMemberUpdateMsg, "plMemberUpdateMsg" },
  { live_plNetMsgPagingRoom, "plNetMsgPagingRoom" },
  { live_plActivatorMsg, "plActivatorMsg" },
  { live_plDispatch, "plDispatch" },
  { live_plReceiver, "plReceiver" },
  { live_plMeshRefMsg, "plMeshRefMsg" },
  { live_hsGRenderProcs, "hsGRenderProcs" },
  { live_hsSfxAngleFade, "hsSfxAngleFade" },
  { live_hsSfxDistFade, "hsSfxDistFade" },
  { live_hsSfxDistShade, "hsSfxDistShade" },
  { live_hsSfxGlobalShade, "hsSfxGlobalShade" },
  { live_hsSfxIntenseAlpha, "hsSfxIntenseAlpha" },
  { live_hsSfxObjDistFade, "hsSfxObjDistFade" },
  { live_hsSfxObjDistShade, "hsSfxObjDistShade" },
  { live_hsDynamicValue, "hsDynamicValue" },
  { live_hsDynamicScalar, "hsDynamicScalar" },
  { live_hsDynamicColorRGBA, "hsDynamicColorRGBA" },
  { live_hsDynamicMatrix33, "hsDynamicMatrix33" },
  { live_hsDynamicMatrix44, "hsDynamicMatrix44" },
  { live_plOmniSqApplicator, "plOmniSqApplicator" },
  { live_plPreResourceMsg, "plPreResourceMsg" },
  { live_UNUSED_hsDynamicColorRGBA, "UNUSED_hsDynamicColorRGBA" },
  { live_UNUSED_hsDynamicMatrix33, "UNUSED_hsDynamicMatrix33" },
  { live_UNUSED_hsDynamicMatrix44, "UNUSED_hsDynamicMatrix44" },
  { live_plController, "plController" },
  { live_plLeafController, "plLeafController" },
  { live_plCompoundController, "plCompoundController" },
  { live_UNUSED_plRotController, "UNUSED_plRotController" },
  { live_UNUSED_plPosController, "UNUSED_plPosController" },
  { live_UNUSED_plScalarController, "UNUSED_plScalarController" },
  { live_UNUSED_plPoint3Controller, "UNUSED_plPoint3Controller" },
  { live_UNUSED_plScaleValueController, "UNUSED_plScaleValueController" },
  { live_UNUSED_plQuatController, "UNUSED_plQuatController" },
  { live_UNUSED_plMatrix33Controller, "UNUSED_plMatrix33Controller" },
  { live_UNUSED_plMatrix44Controller, "UNUSED_plMatrix44Controller" },
  { live_UNUSED_plEaseController, "UNUSED_plEaseController" },
  { live_UNUSED_plSimpleScaleController, "UNUSED_plSimpleScaleController" },
  { live_UNUSED_plSimpleRotController, "UNUSED_plSimpleRotController" },
  { live_plCompoundRotController, "plCompoundRotController" },
  { live_UNUSED_plSimplePosController, "UNUSED_plSimplePosController" },
  { live_plCompoundPosController, "plCompoundPosController" },
  { live_plTMController, "plTMController" },
  { live_hsFogControl, "hsFogControl" },
  { live_plIntRefMsg, "plIntRefMsg" },
  { live_plCollisionReactor, "plCollisionReactor" },
  { live_plCorrectionMsg, "plCorrectionMsg" },
  { live_plPhysicalModifier, "plPhysicalModifier" },
  { live_plPickedMsg, "plPickedMsg" },
  { live_plCollideMsg, "plCollideMsg" },
  { live_plTriggerMsg, "plTriggerMsg" },
  { live_plInterestingModMsg, "plInterestingModMsg" },
  { live_plDebugKeyEventMsg, "plDebugKeyEventMsg" },
  { live_plPhysicalProperties_DEAD, "plPhysicalProperties_DEAD" },
  { live_plSimplePhys, "plSimplePhys" },
  { live_plMatrixUpdateMsg, "plMatrixUpdateMsg" },
  { live_plCondRefMsg, "plCondRefMsg" },
  { live_plTimerCallbackMsg, "plTimerCallbackMsg" },
  { live_plEventCallbackMsg, "plEventCallbackMsg" },
  { live_plSpawnModMsg, "plSpawnModMsg" },
  { live_plSpawnRequestMsg, "plSpawnRequestMsg" },
  { live_plLoadCloneMsg, "plLoadCloneMsg" },
  { live_plEnableMsg, "plEnableMsg" },
  { live_plWarpMsg, "plWarpMsg" },
  { live_plAttachMsg, "plAttachMsg" },
  { live_pfConsole, "pfConsole" },
  { live_plRenderMsg, "plRenderMsg" },
  { live_plAnimTimeConvert, "plAnimTimeConvert" },
  { live_plSoundMsg, "plSoundMsg" },
  { live_plInterestingPing, "plInterestingPing" },
  { live_plNodeCleanupMsg, "plNodeCleanupMsg" },
  { live_plSpaceTree, "plSpaceTree" },
  { live_plNetMessage, "plNetMessage" },
  { live_plNetMsgJoinReq, "plNetMsgJoinReq" },
  { live_plNetMsgJoinAck, "plNetMsgJoinAck" },
  { live_plNetMsgLeave, "plNetMsgLeave" },
  { live_plNetMsgPing, "plNetMsgPing" },
  { live_plNetMsgRoomsList, "plNetMsgRoomsList" },
  { live_plNetMsgGroupOwner, "plNetMsgGroupOwner" },
  { live_plNetMsgGameStateRequest, "plNetMsgGameStateRequest" },
  { live_plNetMsgSessionReset, "plNetMsgSessionReset" },
  { live_plNetMsgOmnibus, "plNetMsgOmnibus" },
  { live_plNetMsgObject, "plNetMsgObject" },
  { live_plCCRInvisibleMsg, "plCCRInvisibleMsg" },
  { live_plLinkInDoneMsg, "plLinkInDoneMsg" },
  { live_plNetMsgGameMessage, "plNetMsgGameMessage" },
  { live_plNetMsgStream, "plNetMsgStream" },
  { live_plAudioSysMsg, "plAudioSysMsg" },
  { live_plDispatchBase, "plDispatchBase" },
  { live_plServerReplyMsg, "plServerReplyMsg" },
  { live_plDeviceRecreateMsg, "plDeviceRecreateMsg" },
  { live_plNetMsgStreamHelper, "plNetMsgStreamHelper" },
  { live_plNetMsgObjectHelper, "plNetMsgObjectHelper" },
  { live_plIMouseXEventMsg, "plIMouseXEventMsg" },
  { live_plIMouseYEventMsg, "plIMouseYEventMsg" },
  { live_plIMouseBEventMsg, "plIMouseBEventMsg" },
  { live_plLogicTriggerMsg, "plLogicTriggerMsg" },
  { live_plPipeline, "plPipeline" },
  { live_plDXPipeline, "plDXPipeline" },
  { live_plNetMsgVoice, "plNetMsgVoice" },
  { live_plLightRefMsg, "plLightRefMsg" },
  { live_plNetMsgStreamedObject, "plNetMsgStreamedObject" },
  { live_plNetMsgSharedState, "plNetMsgSharedState" },
  { live_plNetMsgTestAndSet, "plNetMsgTestAndSet" },
  { live_plNetMsgGetSharedState, "plNetMsgGetSharedState" },
  { live_plSharedStateMsg, "plSharedStateMsg" },
  { live_plNetGenericServerTask, "plNetGenericServerTask" },
  { live_plNetClientMgrMsg, "plNetClientMgrMsg" },
  { live_plLoadAgeMsg, "plLoadAgeMsg" },
  { live_plMessageWithCallbacks, "plMessageWithCallbacks" },
  { live_plClientMsg, "plClientMsg" },
  { live_plClientRefMsg, "plClientRefMsg" },
  { live_plNetMsgObjStateRequest, "plNetMsgObjStateRequest" },
  { live_plCCRPetitionMsg, "plCCRPetitionMsg" },
  { live_plVaultCCRInitializationTask, "plVaultCCRInitializationTask" },
  { live_plNetServerMsg, "plNetServerMsg" },
  { live_plNetServerMsgWithContext, "plNetServerMsgWithContext" },
  { live_plNetServerMsgRegisterServer, "plNetServerMsgRegisterServer" },
  { live_plNetServerMsgUnregisterServer, "plNetServerMsgUnregisterServer" },
  { live_plNetServerMsgStartProcess, "plNetServerMsgStartProcess" },
  { live_plNetServerMsgRegisterProcess, "plNetServerMsgRegisterProcess" },
  { live_plNetServerMsgUnregisterProcess, "plNetServerMsgUnregisterProcess" },
  { live_plNetServerMsgFindProcess, "plNetServerMsgFindProcess" },
  { live_plNetServerMsgProcessFound, "plNetServerMsgProcessFound" },
  { live_plNetMsgRoutingInfo, "plNetMsgRoutingInfo" },
  { live_plNetServerSessionInfo, "plNetServerSessionInfo" },
  { live_plSimulationMsg, "plSimulationMsg" },
  { live_plSimulationSynchMsg, "plSimulationSynchMsg" },
  { live_plHKSimulationSynchMsg, "plHKSimulationSynchMsg" },
  { live_plAvatarMsg, "plAvatarMsg" },
  { live_plAvTaskMsg, "plAvTaskMsg" },
  { live_plAvSeekMsg, "plAvSeekMsg" },
  { live_plAvOneShotMsg, "plAvOneShotMsg" },
  { live_plSatisfiedMsg, "plSatisfiedMsg" },
  { live_plNetMsgObjectListHelper, "plNetMsgObjectListHelper" },
  { live_plNetMsgObjectUpdateFilter, "plNetMsgObjectUpdateFilter" },
  { live_plProxyDrawMsg, "plProxyDrawMsg" },
  { live_plSelfDestructMsg, "plSelfDestructMsg" },
  { live_plSimInfluenceMsg, "plSimInfluenceMsg" },
  { live_plForceMsg, "plForceMsg" },
  { live_plOffsetForceMsg, "plOffsetForceMsg" },
  { live_plTorqueMsg, "plTorqueMsg" },
  { live_plImpulseMsg, "plImpulseMsg" },
  { live_plOffsetImpulseMsg, "plOffsetImpulseMsg" },
  { live_plAngularImpulseMsg, "plAngularImpulseMsg" },
  { live_plDampMsg, "plDampMsg" },
  { live_plShiftMassMsg, "plShiftMassMsg" },
  { live_plSimStateMsg, "plSimStateMsg" },
  { live_plFreezeMsg, "plFreezeMsg" },
  { live_plEventGroupMsg, "plEventGroupMsg" },
  { live_plSuspendEventMsg, "plSuspendEventMsg" },
  { live_plNetMsgMembersListReq, "plNetMsgMembersListReq" },
  { live_plNetMsgMembersList, "plNetMsgMembersList" },
  { live_plNetMsgMemberInfoHelper, "plNetMsgMemberInfoHelper" },
  { live_plNetMsgMemberListHelper, "plNetMsgMemberListHelper" },
  { live_plNetMsgMemberUpdate, "plNetMsgMemberUpdate" },
  { live_plNetMsgServerToClient, "plNetMsgServerToClient" },
  { live_plNetMsgCreatePlayer, "plNetMsgCreatePlayer" },
  { live_plNetMsgAuthenticateHello, "plNetMsgAuthenticateHello" },
  { live_plNetMsgAuthenticateChallenge, "plNetMsgAuthenticateChallenge" },
  { live_plConnectedToVaultMsg, "plConnectedToVaultMsg" },
  { live_plCCRCommunicationMsg, "plCCRCommunicationMsg" },
  { live_plNetMsgInitialAgeStateSent, "plNetMsgInitialAgeStateSent" },
  { live_plInitialAgeStateLoadedMsg, "plInitialAgeStateLoadedMsg" },
  { live_plNetServerMsgFindServerBase, "plNetServerMsgFindServerBase" },
  { live_plNetServerMsgFindServerReplyBase, "plNetServerMsgFindServerReplyBase" },
  { live_plNetServerMsgFindAuthServer, "plNetServerMsgFindAuthServer" },
  { live_plNetServerMsgFindAuthServerReply, "plNetServerMsgFindAuthServerReply" },
  { live_plNetServerMsgFindVaultServer, "plNetServerMsgFindVaultServer" },
  { live_plNetServerMsgFindVaultServerReply, "plNetServerMsgFindVaultServerReply" },
  { live_plAvTaskSeekDoneMsg, "plAvTaskSeekDoneMsg" },
  { live_plNCAgeJoinerMsg, "plNCAgeJoinerMsg" },
  { live_plNetServerMsgVaultTask, "plNetServerMsgVaultTask" },
  { live_plNetMsgVaultTask, "plNetMsgVaultTask" },
  { live_plAgeLinkStruct, "plAgeLinkStruct" },
  { live_plVaultAgeInfoNode, "plVaultAgeInfoNode" },
  { live_plNetMsgStreamableHelper, "plNetMsgStreamableHelper" },
  { live_plNetMsgReceiversListHelper, "plNetMsgReceiversListHelper" },
  { live_plNetMsgListenListUpdate, "plNetMsgListenListUpdate" },
  { live_plNetServerMsgPing, "plNetServerMsgPing" },
  { live_plNetMsgAlive, "plNetMsgAlive" },
  { live_plNetMsgTerminated, "plNetMsgTerminated" },
  { live_plSDLModifierMsg, "plSDLModifierMsg" },
  { live_plNetMsgSDLState, "plNetMsgSDLState" },
  { live_plNetServerMsgSessionReset, "plNetServerMsgSessionReset" },
  { live_plCCRBanLinkingMsg, "plCCRBanLinkingMsg" },
  { live_plCCRSilencePlayerMsg, "plCCRSilencePlayerMsg" },
  { live_plRenderRequestMsg, "plRenderRequestMsg" },
  { live_plRenderRequestAck, "plRenderRequestAck" },
  { live_plNetMember, "plNetMember" },
  { live_plNetGameMember, "plNetGameMember" },
  { live_plNetTransportMember, "plNetTransportMember" },
  { live_plConvexVolume, "plConvexVolume" },
  { live_plParticleGenerator, "plParticleGenerator" },
  { live_plSimpleParticleGenerator, "plSimpleParticleGenerator" },
  { live_plParticleEmitter, "plParticleEmitter" },
  { live_plAGChannel, "plAGChannel" },
  { live_plMatrixChannel, "plMatrixChannel" },
  { live_plMatrixTimeScale, "plMatrixTimeScale" },
  { live_plMatrixBlend, "plMatrixBlend" },
  { live_plMatrixControllerChannel, "plMatrixControllerChannel" },
  { live_plQuatPointCombine, "plQuatPointCombine" },
  { live_plPointChannel, "plPointChannel" },
  { live_plPointConstant, "plPointConstant" },
  { live_plPointBlend, "plPointBlend" },
  { live_plQuatChannel, "plQuatChannel" },
  { live_plQuatConstant, "plQuatConstant" },
  { live_plQuatBlend, "plQuatBlend" },
  { live_plLinkToAgeMsg, "plLinkToAgeMsg" },
  { live_plPlayerPageMsg, "plPlayerPageMsg" },
  { live_plCmdIfaceModMsg, "plCmdIfaceModMsg" },
  { live_plNetServerMsgPlsUpdatePlayer, "plNetServerMsgPlsUpdatePlayer" },
  { live_plListenerMsg, "plListenerMsg" },
  { live_plAnimPath, "plAnimPath" },
  { live_plClothingUpdateBCMsg, "plClothingUpdateBCMsg" },
  { live_plNotifyMsg, "plNotifyMsg" },
  { live_plFakeOutMsg, "plFakeOutMsg" },
  { live_plCursorChangeMsg, "plCursorChangeMsg" },
  { live_plNodeChangeMsg, "plNodeChangeMsg" },
  { live_UNUSED_plAvEnableMsg, "UNUSED_plAvEnableMsg" },
  { live_plLinkCallbackMsg, "plLinkCallbackMsg" },
  { live_plTransitionMsg, "plTransitionMsg" },
  { live_plConsoleMsg, "plConsoleMsg" },
  { live_plVolumeIsect, "plVolumeIsect" },
  { live_plSphereIsect, "plSphereIsect" },
  { live_plConeIsect, "plConeIsect" },
  { live_plCylinderIsect, "plCylinderIsect" },
  { live_plParallelIsect, "plParallelIsect" },
  { live_plConvexIsect, "plConvexIsect" },
  { live_plComplexIsect, "plComplexIsect" },
  { live_plUnionIsect, "plUnionIsect" },
  { live_plIntersectionIsect, "plIntersectionIsect" },
  { live_plModulator, "plModulator" },
  { live_UNUSED___plInventoryMsg, "UNUSED___plInventoryMsg" },
  { live_plLinkEffectsTriggerMsg, "plLinkEffectsTriggerMsg" },
  { live_plLinkEffectBCMsg, "plLinkEffectBCMsg" },
  { live_plResponderEnableMsg, "plResponderEnableMsg" },
  { live_plNetServerMsgHello, "plNetServerMsgHello" },
  { live_plNetServerMsgHelloReply, "plNetServerMsgHelloReply" },
  { live_plNetServerMember, "plNetServerMember" },
  { live_plResponderMsg, "plResponderMsg" },
  { live_plOneShotMsg, "plOneShotMsg" },
  { live_plVaultAgeInfoListNode, "plVaultAgeInfoListNode" },
  { live_plNetServerMsgServerRegistered, "plNetServerMsgServerRegistered" },
  { live_plPointTimeScale, "plPointTimeScale" },
  { live_plPointControllerChannel, "plPointControllerChannel" },
  { live_plQuatTimeScale, "plQuatTimeScale" },
  { live_plAGApplicator, "plAGApplicator" },
  { live_plMatrixChannelApplicator, "plMatrixChannelApplicator" },
  { live_plPointChannelApplicator, "plPointChannelApplicator" },
  { live_plLightDiffuseApplicator, "plLightDiffuseApplicator" },
  { live_plLightAmbientApplicator, "plLightAmbientApplicator" },
  { live_plLightSpecularApplicator, "plLightSpecularApplicator" },
  { live_plOmniApplicator, "plOmniApplicator" },
  { live_plQuatChannelApplicator, "plQuatChannelApplicator" },
  { live_plScalarChannel, "plScalarChannel" },
  { live_plScalarTimeScale, "plScalarTimeScale" },
  { live_plScalarBlend, "plScalarBlend" },
  { live_plScalarControllerChannel, "plScalarControllerChannel" },
  { live_plScalarChannelApplicator, "plScalarChannelApplicator" },
  { live_plSpotInnerApplicator, "plSpotInnerApplicator" },
  { live_plSpotOuterApplicator, "plSpotOuterApplicator" },
  { live_plNetServerMsgPlsRoutableMsg, "plNetServerMsgPlsRoutableMsg" },
  { live__UNUSED_plPuppetBrainMsg, "_UNUSED_plPuppetBrainMsg" },
  { live_plATCEaseCurve, "plATCEaseCurve" },
  { live_plConstAccelEaseCurve, "plConstAccelEaseCurve" },
  { live_plSplineEaseCurve, "plSplineEaseCurve" },
  { live_plVaultAgeInfoInitializationTask, "plVaultAgeInfoInitializationTask" },
  { live_pfGameGUIMsg, "pfGameGUIMsg" },
  { live_plNetServerMsgVaultRequestGameState, "plNetServerMsgVaultRequestGameState" },
  { live_plNetServerMsgVaultGameState, "plNetServerMsgVaultGameState" },
  { live_plNetServerMsgVaultGameStateSave, "plNetServerMsgVaultGameStateSave" },
  { live_plNetServerMsgVaultGameStateSaved, "plNetServerMsgVaultGameStateSaved" },
  { live_plNetServerMsgVaultGameStateLoad, "plNetServerMsgVaultGameStateLoad" },
  { live_plNetClientTask, "plNetClientTask" },
  { live_plNetMsgSDLStateBCast, "plNetMsgSDLStateBCast" },
  { live_plReplaceGeometryMsg, "plReplaceGeometryMsg" },
  { live_plNetServerMsgExitProcess, "plNetServerMsgExitProcess" },
  { live_plNetServerMsgSaveGameState, "plNetServerMsgSaveGameState" },
  { live_plDniCoordinateInfo, "plDniCoordinateInfo" },
  { live_plNetMsgGameMessageDirected, "plNetMsgGameMessageDirected" },
  { live_plLinkOutUnloadMsg, "plLinkOutUnloadMsg" },
  { live_plScalarConstant, "plScalarConstant" },
  { live_plMatrixConstant, "plMatrixConstant" },
  { live_plAGCmdMsg, "plAGCmdMsg" },
  { live_plParticleTransferMsg, "plParticleTransferMsg" },
  { live_plParticleKillMsg, "plParticleKillMsg" },
  { live_plExcludeRegionMsg, "plExcludeRegionMsg" },
  { live_plOneTimeParticleGenerator, "plOneTimeParticleGenerator" },
  { live_plParticleApplicator, "plParticleApplicator" },
  { live_plParticleLifeMinApplicator, "plParticleLifeMinApplicator" },
  { live_plParticleLifeMaxApplicator, "plParticleLifeMaxApplicator" },
  { live_plParticlePPSApplicator, "plParticlePPSApplicator" },
  { live_plParticleAngleApplicator, "plParticleAngleApplicator" },
  { live_plParticleVelMinApplicator, "plParticleVelMinApplicator" },
  { live_plParticleVelMaxApplicator, "plParticleVelMaxApplicator" },
  { live_plParticleScaleMinApplicator, "plParticleScaleMinApplicator" },
  { live_plParticleScaleMaxApplicator, "plParticleScaleMaxApplicator" },
  { live_plDynamicTextMsg, "plDynamicTextMsg" },
  { live_plCameraTargetFadeMsg, "plCameraTargetFadeMsg" },
  { live_plAgeLoadedMsg, "plAgeLoadedMsg" },
  { live_plPointControllerCacheChannel, "plPointControllerCacheChannel" },
  { live_plScalarControllerCacheChannel, "plScalarControllerCacheChannel" },
  { live_plLinkEffectsTriggerPrepMsg, "plLinkEffectsTriggerPrepMsg" },
  { live_plLinkEffectPrepBCMsg, "plLinkEffectPrepBCMsg" },
  { live_plAvatarInputStateMsg, "plAvatarInputStateMsg" },
  { live_plAgeInfoStruct, "plAgeInfoStruct" },
  { live_plSDLNotificationMsg, "plSDLNotificationMsg" },
  { live_plNetClientConnectAgeVaultTask, "plNetClientConnectAgeVaultTask" },
  { live_plLinkingMgrMsg, "plLinkingMgrMsg" },
  { live_plVaultNotifyMsg, "plVaultNotifyMsg" },
  { live_plPlayerInfo, "plPlayerInfo" },
  { live_plSwapSpansRefMsg, "plSwapSpansRefMsg" },
  { live_pfKI, "pfKI" },
  { live_plDISpansMsg, "plDISpansMsg" },
  { live_plNetMsgCreatableHelper, "plNetMsgCreatableHelper" },
  { live_plCreatableUuid, "plCreatableUuid" },
  { live_plNetMsgRequestMyVaultPlayerList, "plNetMsgRequestMyVaultPlayerList" },
  { live_plDelayedTransformMsg, "plDelayedTransformMsg" },
  { live_plSuperVNodeMgrInitTask, "plSuperVNodeMgrInitTask" },
  { live_plElementRefMsg, "plElementRefMsg" },
  { live_plClothingMsg, "plClothingMsg" },
  { live_plEventGroupEnableMsg, "plEventGroupEnableMsg" },
  { live_pfGUINotifyMsg, "pfGUINotifyMsg" },
  { live_UNUSED_plAvBrain, "UNUSED_plAvBrain" },
  { live_plArmatureBrain, "plArmatureBrain" },
  { live_plAvBrainHuman, "plAvBrainHuman" },
  { live_plAvBrainCritter, "plAvBrainCritter" },
  { live_plAvBrainDrive, "plAvBrainDrive" },
  { live_plAvBrainSample, "plAvBrainSample" },
  { live_plAvBrainGeneric, "plAvBrainGeneric" },
  { live_plPreloaderMsg, "plPreloaderMsg" },
  { live_plAvBrainLadder, "plAvBrainLadder" },
  { live_plInputIfaceMgrMsg, "plInputIfaceMgrMsg" },
  { live_pfKIMsg, "pfKIMsg" },
  { live_plRemoteAvatarInfoMsg, "plRemoteAvatarInfoMsg" },
  { live_plMatrixDelayedCorrectionApplicator, "plMatrixDelayedCorrectionApplicator" },
  { live_plAvPushBrainMsg, "plAvPushBrainMsg" },
  { live_plAvPopBrainMsg, "plAvPopBrainMsg" },
  { live_plRoomLoadNotifyMsg, "plRoomLoadNotifyMsg" },
  { live_plAvTask, "plAvTask" },
  { live_plAvAnimTask, "plAvAnimTask" },
  { live_plAvSeekTask, "plAvSeekTask" },
  { live_plNetCommAuthConnectedMsg, "plNetCommAuthConnectedMsg" },
  { live_plAvOneShotTask, "plAvOneShotTask" },
  { live_UNUSED_plAvEnableTask, "UNUSED_plAvEnableTask" },
  { live_plAvTaskBrain, "plAvTaskBrain" },
  { live_plAnimStage, "plAnimStage" },
  { live_plNetClientMember, "plNetClientMember" },
  { live_plNetClientCommTask, "plNetClientCommTask" },
  { live_plNetServerMsgAuthRequest, "plNetServerMsgAuthRequest" },
  { live_plNetServerMsgAuthReply, "plNetServerMsgAuthReply" },
  { live_plNetClientCommAuthTask, "plNetClientCommAuthTask" },
  { live_plClientGuid, "plClientGuid" },
  { live_plNetMsgVaultPlayerList, "plNetMsgVaultPlayerList" },
  { live_plNetMsgSetMyActivePlayer, "plNetMsgSetMyActivePlayer" },
  { live_plNetServerMsgRequestAccountPlayerList, "plNetServerMsgRequestAccountPlayerList" },
  { live_plNetServerMsgAccountPlayerList, "plNetServerMsgAccountPlayerList" },
  { live_plNetMsgPlayerCreated, "plNetMsgPlayerCreated" },
  { live_plNetServerMsgVaultCreatePlayer, "plNetServerMsgVaultCreatePlayer" },
  { live_plNetServerMsgVaultPlayerCreated, "plNetServerMsgVaultPlayerCreated" },
  { live_plNetMsgFindAge, "plNetMsgFindAge" },
  { live_plNetMsgFindAgeReply, "plNetMsgFindAgeReply" },
  { live_plNetClientConnectPrepTask, "plNetClientConnectPrepTask" },
  { live_plNetClientAuthTask, "plNetClientAuthTask" },
  { live_plNetClientGetPlayerVaultTask, "plNetClientGetPlayerVaultTask" },
  { live_plNetClientSetActivePlayerTask, "plNetClientSetActivePlayerTask" },
  { live_plNetClientFindAgeTask, "plNetClientFindAgeTask" },
  { live_plNetClientLeaveTask, "plNetClientLeaveTask" },
  { live_plNetClientJoinTask, "plNetClientJoinTask" },
  { live_plNetClientCalibrateTask, "plNetClientCalibrateTask" },
  { live_plNetMsgDeletePlayer, "plNetMsgDeletePlayer" },
  { live_plNetServerMsgVaultDeletePlayer, "plNetServerMsgVaultDeletePlayer" },
  { live_plNetCoreStatsSummary, "plNetCoreStatsSummary" },
  { live_plCreatableGenericValue, "plCreatableGenericValue" },
  { live_plCreatableListHelper, "plCreatableListHelper" },
  { live_plCreatableStream, "plCreatableStream" },
  { live_plAvBrainGenericMsg, "plAvBrainGenericMsg" },
  { live_plAvTaskSeek, "plAvTaskSeek" },
  { live_plAGInstanceCallbackMsg, "plAGInstanceCallbackMsg" },
  { live_plArmatureEffectMsg, "plArmatureEffectMsg" },
  { live_plArmatureEffectStateMsg, "plArmatureEffectStateMsg" },
  { live_plShadowCastMsg, "plShadowCastMsg" },
  { live_plBoundsIsect, "plBoundsIsect" },
  { live_plResMgrHelperMsg, "plResMgrHelperMsg" },
  { live_plNetCommAuthMsg, "plNetCommAuthMsg" },
  { live_plNetCommFileListMsg, "plNetCommFileListMsg" },
  { live_plNetCommFileDownloadMsg, "plNetCommFileDownloadMsg" },
  { live_plNetCommLinkToAgeMsg, "plNetCommLinkToAgeMsg" },
  { live_plNetCommPlayerListMsg, "plNetCommPlayerListMsg" },
  { live_plNetCommActivePlayerMsg, "plNetCommActivePlayerMsg" },
  { live_plNetCommCreatePlayerMsg, "plNetCommCreatePlayerMsg" },
  { live_plNetCommDeletePlayerMsg, "plNetCommDeletePlayerMsg" },
  { live_plNetCommPublicAgeListMsg, "plNetCommPublicAgeListMsg" },
  { live_plNetCommPublicAgeMsg, "plNetCommPublicAgeMsg" },
  { live_plNetCommRegisterAgeMsg, "plNetCommRegisterAgeMsg" },
  { live_plVaultAdminInitializationTask, "plVaultAdminInitializationTask" },
  { live_plMultistageModMsg, "plMultistageModMsg" },
  { live_plSoundVolumeApplicator, "plSoundVolumeApplicator" },
  { live_plCutter, "plCutter" },
  { live_plBulletMsg, "plBulletMsg" },
  { live_plDynaDecalEnableMsg, "plDynaDecalEnableMsg" },
  { live_plOmniCutoffApplicator, "plOmniCutoffApplicator" },
  { live_plArmatureUpdateMsg, "plArmatureUpdateMsg" },
  { live_plAvatarFootMsg, "plAvatarFootMsg" },
  { live_plNetOwnershipMsg, "plNetOwnershipMsg" },
  { live_plNetMsgRelevanceRegions, "plNetMsgRelevanceRegions" },
  { live_plParticleFlockMsg, "plParticleFlockMsg" },
  { live_plAvatarBehaviorNotifyMsg, "plAvatarBehaviorNotifyMsg" },
  { live_plATCChannel, "plATCChannel" },
  { live_plScalarSDLChannel, "plScalarSDLChannel" },
  { live_plLoadAvatarMsg, "plLoadAvatarMsg" },
  { live_plAvatarSetTypeMsg, "plAvatarSetTypeMsg" },
  { live_plNetMsgLoadClone, "plNetMsgLoadClone" },
  { live_plNetMsgPlayerPage, "plNetMsgPlayerPage" },
  { live_plVNodeInitTask, "plVNodeInitTask" },
  { live_plRippleShapeMsg, "plRippleShapeMsg" },
  { live_plEventManager, "plEventManager" },
  { live_plVaultNeighborhoodInitializationTask, "plVaultNeighborhoodInitializationTask" },
  { live_plNetServerMsgAgentRecoveryRequest, "plNetServerMsgAgentRecoveryRequest" },
  { live_plNetServerMsgFrontendRecoveryRequest, "plNetServerMsgFrontendRecoveryRequest" },
  { live_plNetServerMsgBackendRecoveryRequest, "plNetServerMsgBackendRecoveryRequest" },
  { live_plNetServerMsgAgentRecoveryData, "plNetServerMsgAgentRecoveryData" },
  { live_plNetServerMsgFrontendRecoveryData, "plNetServerMsgFrontendRecoveryData" },
  { live_plNetServerMsgBackendRecoveryData, "plNetServerMsgBackendRecoveryData" },
  { live_plSubWorldMsg, "plSubWorldMsg" },
  { live_plMatrixDifferenceApp, "plMatrixDifferenceApp" },
  { live_plAvatarSpawnNotifyMsg, "plAvatarSpawnNotifyMsg" },
  { live_plVaultGameServerInitializationTask, "plVaultGameServerInitializationTask" },
  { live_plNetClientFindDefaultAgeTask, "plNetClientFindDefaultAgeTask" },
  { live_plVaultAgeNode, "plVaultAgeNode" },
  { live_plVaultAgeInitializationTask, "plVaultAgeInitializationTask" },
  { live_plSetListenerMsg, "plSetListenerMsg" },
  { live_plVaultSystemNode, "plVaultSystemNode" },
  { live_plAvBrainSwim, "plAvBrainSwim" },
  { live_plNetMsgVault, "plNetMsgVault" },
  { live_plNetServerMsgVault, "plNetServerMsgVault" },
  { live_plVaultTask, "plVaultTask" },
  { live_plVaultConnectTask, "plVaultConnectTask" },
  { live_plVaultNegotiateManifestTask, "plVaultNegotiateManifestTask" },
  { live_plVaultFetchNodesTask, "plVaultFetchNodesTask" },
  { live_plVaultSaveNodeTask, "plVaultSaveNodeTask" },
  { live_plVaultFindNodeTask, "plVaultFindNodeTask" },
  { live_plVaultAddNodeRefTask, "plVaultAddNodeRefTask" },
  { live_plVaultRemoveNodeRefTask, "plVaultRemoveNodeRefTask" },
  { live_plVaultSendNodeTask, "plVaultSendNodeTask" },
  { live_plVaultNotifyOperationCallbackTask, "plVaultNotifyOperationCallbackTask" },
  { live_plVNodeMgrInitializationTask, "plVNodeMgrInitializationTask" },
  { live_plVaultPlayerInitializationTask, "plVaultPlayerInitializationTask" },
  { live_plNetVaultServerInitializationTask, "plNetVaultServerInitializationTask" },
  { live_plCommonNeighborhoodsInitTask, "plCommonNeighborhoodsInitTask" },
  { live_plVaultNodeRef, "plVaultNodeRef" },
  { live_plVaultNode, "plVaultNode" },
  { live_plVaultFolderNode, "plVaultFolderNode" },
  { live_plVaultImageNode, "plVaultImageNode" },
  { live_plVaultTextNoteNode, "plVaultTextNoteNode" },
  { live_plVaultSDLNode, "plVaultSDLNode" },
  { live_plVaultAgeLinkNode, "plVaultAgeLinkNode" },
  { live_plVaultChronicleNode, "plVaultChronicleNode" },
  { live_plVaultPlayerInfoNode, "plVaultPlayerInfoNode" },
  { live_plVaultMgrNode, "plVaultMgrNode" },
  { live_plVaultPlayerNode, "plVaultPlayerNode" },
  { live_plSynchEnableMsg, "plSynchEnableMsg" },
  { live_plNetVaultServerNode, "plNetVaultServerNode" },
  { live_plVaultAdminNode, "plVaultAdminNode" },
  { live_plVaultGameServerNode, "plVaultGameServerNode" },
  { live_plVaultPlayerInfoListNode, "plVaultPlayerInfoListNode" },
  { live_plAvatarStealthModeMsg, "plAvatarStealthModeMsg" },
  { live_plEventCallbackInterceptMsg, "plEventCallbackInterceptMsg" },
  { live_plDynamicEnvMapMsg, "plDynamicEnvMapMsg" },
  { live_plClimbMsg, "plClimbMsg" },
  { live_plIfaceFadeAvatarMsg, "plIfaceFadeAvatarMsg" },
  { live_plAvBrainClimb, "plAvBrainClimb" },
  { live_plSharedMeshBCMsg, "plSharedMeshBCMsg" },
  { live_plNetVoiceListMsg, "plNetVoiceListMsg" },
  { live_plSwimMsg, "plSwimMsg" },
  { live_plMorphDelta, "plMorphDelta" },
  { live_plMatrixControllerCacheChannel, "plMatrixControllerCacheChannel" },
  { live_plVaultMarkerNode, "plVaultMarkerNode" },
  { live_pfMarkerMsg, "pfMarkerMsg" },
  { live_plPipeResMakeMsg, "plPipeResMakeMsg" },
  { live_plPipeRTMakeMsg, "plPipeRTMakeMsg" },
  { live_plPipeGeoMakeMsg, "plPipeGeoMakeMsg" },
  { live_plAvCoopMsg, "plAvCoopMsg" },
  { live_plAvBrainCoop, "plAvBrainCoop" },
  { live_plSimSuppressMsg, "plSimSuppressMsg" },
  { live_plVaultMarkerListNode, "plVaultMarkerListNode" },
  { live_UNUSED_plAvTaskOrient, "UNUSED_plAvTaskOrient" },
  { live_plAgeBeginLoadingMsg, "plAgeBeginLoadingMsg" },
  { live_plSetNetGroupIDMsg, "plSetNetGroupIDMsg" },
  { live_pfBackdoorMsg, "pfBackdoorMsg" },
  { live_plAIMsg, "plAIMsg" },
  { live_plAIBrainCreatedMsg, "plAIBrainCreatedMsg" },
  { live_plStateDataRecord, "plStateDataRecord" },
  { live_plNetClientCommDeletePlayerTask, "plNetClientCommDeletePlayerTask" },
  { live_plNetMsgSetTimeout, "plNetMsgSetTimeout" },
  { live_plNetMsgActivePlayerSet, "plNetMsgActivePlayerSet" },
  { live_plNetClientCommSetTimeoutTask, "plNetClientCommSetTimeoutTask" },
  { live_plNetRoutableMsgOmnibus, "plNetRoutableMsgOmnibus" },
  { live_plNetMsgGetPublicAgeList, "plNetMsgGetPublicAgeList" },
  { live_plNetMsgPublicAgeList, "plNetMsgPublicAgeList" },
  { live_plNetMsgCreatePublicAge, "plNetMsgCreatePublicAge" },
  { live_plNetMsgPublicAgeCreated, "plNetMsgPublicAgeCreated" },
  { live_plNetServerMsgEnvelope, "plNetServerMsgEnvelope" },
  { live_plNetClientCommGetPublicAgeListTask, "plNetClientCommGetPublicAgeListTask" },
  { live_plNetClientCommCreatePublicAgeTask, "plNetClientCommCreatePublicAgeTask" },
  { live_plNetServerMsgPendingMsgs, "plNetServerMsgPendingMsgs" },
  { live_plNetServerMsgRequestPendingMsgs, "plNetServerMsgRequestPendingMsgs" },
  { live_plDbInterface, "plDbInterface" },
  { live_plDbProxyInterface, "plDbProxyInterface" },
  { live_plDBGenericSQLDB, "plDBGenericSQLDB" },
  { live_pfGameMgrMsg, "pfGameMgrMsg" },
  { live_pfGameCliMsg, "pfGameCliMsg" },
  { live_pfGameCli, "pfGameCli" },
  { live_pfGmTicTacToe, "pfGmTicTacToe" },
  { live_pfGmHeek, "pfGmHeek" },
  { live_pfGmMarker, "pfGmMarker" },
  { live_pfGmBlueSpiral, "pfGmBlueSpiral" },
  { live_pfGmClimbingWall, "pfGmClimbingWall" },
  { live_plAIArrivedAtGoalMsg, "plAIArrivedAtGoalMsg" },
  { live_pfGmVarSync, "pfGmVarSync" },
  { live_plNetMsgRemovePublicAge, "plNetMsgRemovePublicAge" },
  { live_plNetMsgPublicAgeRemoved, "plNetMsgPublicAgeRemoved" },
  { live_plNetClientCommRemovePublicAgeTask, "plNetClientCommRemovePublicAgeTask" },
  { live_plCCRMessage, "plCCRMessage" },
  { live_plAvOneShotLinkTask, "plAvOneShotLinkTask" },
  { live_plNetAuthDatabase, "plNetAuthDatabase" },
  { live_plAvatarOpacityCallbackMsg, "plAvatarOpacityCallbackMsg" },
  { live_plAGDetachCallbackMsg, "plAGDetachCallbackMsg" },
  { live_pfMovieEventMsg, "pfMovieEventMsg" },
  { live_plMovieMsg, "plMovieMsg" },
  { live_plPipeTexMakeMsg, "plPipeTexMakeMsg" },
  { live_plEventLog, "plEventLog" },
  { live_plDbEventLog, "plDbEventLog" },
  { live_plSyslogEventLog, "plSyslogEventLog" },
  { live_plCaptureRenderMsg, "plCaptureRenderMsg" },
  { live_plAgeLoaded2Msg, "plAgeLoaded2Msg" },
  { live_plPseudoLinkEffectMsg, "plPseudoLinkEffectMsg" },
  { live_plPseudoLinkAnimTriggerMsg, "plPseudoLinkAnimTriggerMsg" },
  { live_plPseudoLinkAnimCallbackMsg, "plPseudoLinkAnimCallbackMsg" },
  { live___UNUSED__pfClimbingWallMsg, "__UNUSED__pfClimbingWallMsg" },
  { live_plClimbEventMsg, "plClimbEventMsg" },
  { live___UNUSED__plAvBrainQuab, "__UNUSED__plAvBrainQuab" },
  { live_plAccountUpdateMsg, "plAccountUpdateMsg" },
  { live_plLinearVelocityMsg, "plLinearVelocityMsg" },
  { live_plAngularVelocityMsg, "plAngularVelocityMsg" },
  { live_plRideAnimatedPhysMsg, "plRideAnimatedPhysMsg" },
  { live_plAvBrainRideAnimatedPhysical, "plAvBrainRideAnimatedPhysical" },
#endif
  { 0, NULL }
};

#define NegotiateAuth 0x0a
#define NegotiateFile 0x10
#define NegotiateGame 0x0b
#define NegotiateGate 0x16
#define NegotiateNonce 0x00
#define NegotiateNonceResp 0x01

static const value_string live_negotypes[] = {
  { NegotiateAuth, "Auth" },
  { NegotiateFile, "File" },
  { NegotiateGame, "Game" },
  { NegotiateGate, "GateKeeper" },
  { NegotiateNonce, "nonce" },
  { NegotiateNonceResp, "nonce response" },
  { 0, NULL }
};

static const value_string live_client_msgtypes_v1[] = {
  { kCli2Auth_PingRequest_v1, "Cli2Auth/Cli2Game PingRequest"},
  { kCli2Auth_ClientRegisterRequest_v1, "Cli2Auth ClientRegisterRequest" },
  { kCli2Auth_ClientSetCCRLevel_v1, "Cli2Auth ClientSetCCRLevel" },
  { kCli2Auth_AcctLoginRequest_v1, "Cli2Auth AcctLoginRequest or Cli2Game JoinAgeRequest" },
  { kCli2Auth_AcctSetPlayerRequest_v1, "Cli2Auth AcctSetPlayerRequest" },
  { kCli2Auth_AcctCreateRequest_v1, "Cli2Auth AcctCreateRequest" },
  { kCli2Auth_AcctChangePasswordRequest_v1, "Cli2Auth AcctChangePasswordRequest" },
  { kCli2Auth_AcctSetRolesRequest_v1, "Cli2Auth AcctSetRolesRequest" },
  { kCli2Auth_AcctSetBillingTypeRequest_v1, "Cli2Auth AcctSetBillingTypeRequest" },
  { kCli2Auth_AcctActivateRequest_v1, "Cli2Auth AcctActivateRequest" },
  { kCli2Auth_AcctCreateFromKeyRequest_v1, "Cli2Auth AcctCreateFromKeyRequest" },
  { kCli2Game_PropagateBuffer_v1, "Cli2Game PropagateBuffer" },
  { kCli2Game_GameMgrMsg_v1, "Cli2Game GameMgrMsg" },
  { kCli2Auth_PlayerDeleteRequest_v1, "Cli2Auth PlayerDeleteRequest" },
  { kCli2Auth_PlayerCreateRequest_v1, "Cli2Auth PlayerCreateRequest" },
  { kCli2Auth_UpgradeVisitorRequest_v1, "Cli2Auth UpgradeVisitorRequest" },
  { kCli2Auth_SetPlayerBanStatusRequest_v1, "Cli2Auth SetPlayerBanStatusRequest" },
  { kCli2Auth_KickPlayer_v1, "Cli2Auth KickPlayer" },
  { kCli2Auth_ChangePlayerNameRequest_v1, "Cli2Auth ChangePlayerNameRequest" },
  { kCli2Auth_VaultNodeCreate_v1, "Cli2Auth VaultNodeCreate" },
  { kCli2Auth_VaultNodeFetch_v1, "Cli2Auth VaultNodeFetch" },
  { kCli2Auth_VaultNodeSave_v1, "Cli2Auth VaultNodeSave" },
  { kCli2Auth_VaultNodeAdd_v1, "Cli2Auth VaultNodeAdd" },
  { kCli2Auth_VaultNodeRemove_v1, "Cli2Auth VaultNodeRemove" },
  { kCli2Auth_VaultFetchNodeRefs_v1, "Cli2Auth VaultFetchNodeRefs" },
  { kCli2Auth_VaultInitAgeRequest_v1, "Cli2Auth VaultInitAgeRequest" },
  { kCli2Auth_VaultNodeFind_v1, "Cli2Auth VaultNodeFind" },
  { kCli2Auth_VaultSetSeen_v1, "Cli2Auth VaultSetSeen" },
  { kCli2Auth_VaultSendNode_v1, "Cli2Auth VaultSendNode" },
  { kCli2Auth_VaultScoreAddPoints_v1, "Cli2Auth VaultScoreAddPoints" },
  { kCli2Auth_VaultScoreTransferPoints_v1, "Cli2Auth VaultScoreTransferPoints" },
  { kCli2Auth_AgeRequest_v1, "Cli2Auth AgeRequest" },
  { kCli2Auth_FileListRequest_v1, "Cli2Auth FileListRequest" },
  { kCli2Auth_FileDownloadRequest_v1, "Cli2Auth FileDownloadRequest" },
  { kCli2Auth_FileDownloadChunkAck_v1, "Cli2Auth FileDownloadChunkAck" },
  { kCli2Auth_PropagateBuffer_v1, "Cli2Auth PropagateBuffer" },
  { kCli2Auth_GetPublicAgeList_v1, "Cli2Auth GetPublicAgeList" },
  { kCli2Auth_SetAgePublic_v1, "Cli2Auth SetAgePublic" },
  { kCli2Auth_LogPythonTraceback_v1, "Cli2Auth LogPythonTraceback" },
  { kCli2Auth_LogStackDump_v1, "Cli2Auth LogStackDump" },
  { kCli2Auth_LogClientDebuggerConnect_v1, "Cli2Auth LogClientDebuggerConnect" },
  { 0, NULL }
};

static const value_string live_server_msgtypes_v1[] = {
  { kAuth2Cli_PingReply_v1, "Auth2Cli/Game2Cli PingReply" },
  { kAuth2Cli_ServerAddr_v1, "Auth2Cli ServerAddr" },
  { kAuth2Cli_NotifyNewBuild_v1, "Auth2Cli NotifyNewBuild" },
  { kAuth2Cli_ClientRegisterReply_v1, "Auth2Cli ClientRegisterReply" },
  { kAuth2Cli_AcctLoginReply_v1, "Auth2Cli AcctLoginReply or Game2Cli JoinAgeReply" },
  { kAuth2Cli_AcctPlayerInfo_v1, "Auth2Cli AcctPlayerInfo" },
  { kAuth2Cli_AcctSetPlayerReply_v1, "Auth2Cli AcctSetPlayerReply" },
  { kAuth2Cli_AcctCreateReply_v1, "Auth2Cli AcctCreateReply" },
  { kAuth2Cli_AcctChangePasswordReply_v1, "Auth2Cli AcctChangePasswordReply" },
  { kAuth2Cli_AcctSetRolesReply_v1, "Auth2Cli AcctSetRolesReply" },
  { kAuth2Cli_AcctSetBillingTypeReply_v1, "Auth2Cli AcctSetBillingTypeReply" },
  { kAuth2Cli_AcctActivateReply_v1, "Auth2Cli AcctActivateReply" },
  { kAuth2Cli_AcctCreateFromKeyReply_v1, "Auth2Cli AcctCreateFromKeyReply" },
  { kGame2Cli_PropagateBuffer_v1, "Game2Cli PropagateBuffer" },
  { kGame2Cli_GameMgrMsg_v1, "Game2Cli GameMgrMsg" },
  { kAuth2Cli_PlayerCreateReply_v1, "Auth2Cli PlayerCreateReply" },
  { kAuth2Cli_PlayerDeleteReply_v1, "Auth2Cli PlayerDeleteReply" },
  { kAuth2Cli_UpgradeVisitorReply_v1, "Auth2Cli UpgradeVisitorReply" },
  { kAuth2Cli_SetPlayerBanStatusReply_v1, "Auth2Cli SetPlayerBanStatusReply" },
  { kAuth2Cli_ChangePlayerNameReply_v1, "Auth2Cli ChangePlayerNameReply" },
  { kAuth2Cli_VaultNodeCreated_v1, "Auth2Cli VaultNodeCreated" },
  { kAuth2Cli_VaultNodeFetched_v1, "Auth2Cli VaultNodeFetched" },
  { kAuth2Cli_VaultNodeChanged_v1, "Auth2Cli VaultNodeChanged" },
  { kAuth2Cli_VaultNodeDeleted_v1, "Auth2Cli VaultNodeDeleted" },
  { kAuth2Cli_VaultNodeAdded_v1, "Auth2Cli VaultNodeAdded" },
  { kAuth2Cli_VaultNodeRemoved_v1, "Auth2Cli VaultNodeRemoved" },
  { kAuth2Cli_VaultNodeRefsFetched_v1, "Auth2Cli VaultNodeRefsFetched" },
  { kAuth2Cli_VaultInitAgeReply_v1, "Auth2Cli VaultInitAgeReply" },
  { kAuth2Cli_VaultNodeFindReply_v1, "Auth2Cli VaultNodeFindReply" },
  { kAuth2Cli_VaultSaveNodeReply_v1, "Auth2Cli VaultSaveNodeReply" },
  { kAuth2Cli_VaultAddNodeReply_v1, "Auth2Cli VaultAddNodeReply" },
  { kAuth2Cli_VaultRemoveNodeReply_v1, "Auth2Cli VaultRemoveNodeReply" },
  { kAuth2Cli_AgeReply_v1, "Auth2Cli AgeReply" },
  { kAuth2Cli_FileListReply_v1, "Auth2Cli FileListReply" },
  { kAuth2Cli_FileDownloadChunk_v1, "Auth2Cli FileDownloadChunk" },
  { kAuth2Cli_PropagateBuffer_v1, "Auth2Cli PropagateBuffer" },
  { kAuth2Cli_KickedOff_v1, "Auth2Cli KickedOff" },
  { kAuth2Cli_PublicAgeList_v1, "Auth2Cli PublicAgeList" },
  { 0, NULL }
};

static const value_string live_client_auth_msgtypes8[] = {
  { kCli2Auth_VaultNodeCreate-1, "Cli2Auth VaultNodeCreate" },
  { kCli2Auth_VaultNodeFetch-1, "Cli2Auth VaultNodeFetch" },
  { kCli2Auth_VaultNodeSave-1, "Cli2Auth VaultNodeSave" },
  { kCli2Auth_VaultNodeAdd-1, "Cli2Auth VaultNodeAdd" },
  { kCli2Auth_VaultNodeRemove-1, "Cli2Auth VaultNodeRemove" },
  { kCli2Auth_VaultFetchNodeRefs-1, "Cli2Auth VaultFetchNodeRefs" },
  { kCli2Auth_VaultInitAgeRequest-1, "Cli2Auth VaultInitAgeRequest" },
  { kCli2Auth_VaultNodeFind-1, "Cli2Auth VaultNodeFind" },
  { kCli2Auth_VaultSetSeen-1, "Cli2Auth VaultSetSeen" },
  { kCli2Auth_VaultSendNode-1, "Cli2Auth VaultSendNode" },
  { kCli2Auth_AgeRequest-1, "Cli2Auth AgeRequest" },
  { kCli2Auth_FileListRequest-1, "Cli2Auth FileListRequest" },
  { kCli2Auth_FileDownloadRequest-1, "Cli2Auth FileDownloadRequest" },
  { kCli2Auth_FileDownloadChunkAck-1, "Cli2Auth FileDownloadChunkAck" },
  { kCli2Auth_PropagateBuffer-1, "Cli2Auth PropagateBuffer" },
  { kCli2Auth_GetPublicAgeList-1, "Cli2Auth GetPublicAgeList" },
  { kCli2Auth_SetAgePublic-1, "Cli2Auth SetAgePublic" },
  { kCli2Auth_LogPythonTraceback-1, "Cli2Auth LogPythonTraceback" },
  { kCli2Auth_LogStackDump-1, "Cli2Auth LogStackDump" },
  { kCli2Auth_LogClientDebuggerConnect-1, "Cli2Auth LogClientDebuggerConnect" },
  { kCli2Auth_ScoreCreate-1, "Cli2Auth ScoreCreate" },
  { kCli2Auth_ScoreDelete-1, "Cli2Auth ScoreDelete" },
  { kCli2Auth_ScoreGetScores-1, "Cli2Auth ScoreGetScores" },
  { kCli2Auth_ScoreAddPoints-1, "Cli2Auth ScoreAddPoints" },
  { kCli2Auth_ScoreTransferPoints-1, "Cli2Auth ScoreTransferPoints" },
  { kCli2Auth_ScoreSetPoints-1, "Cli2Auth ScoreSetPoints" },
  { kCli2Auth_ScoreGetRanks-1, "Cli2Auth ScoreGetRanks" },
  { 0, NULL }
};

static const value_string live_server_auth_msgtypes8[] = {
  { kAuth2Cli_VaultNodeCreated-1, "Auth2Cli VaultNodeCreated" },
  { kAuth2Cli_VaultNodeFetched-1, "Auth2Cli VaultNodeFetched" },
  { kAuth2Cli_VaultNodeChanged-1, "Auth2Cli VaultNodeChanged" },
  { kAuth2Cli_VaultNodeDeleted-1, "Auth2Cli VaultNodeDeleted" },
  { kAuth2Cli_VaultNodeAdded-1, "Auth2Cli VaultNodeAdded" },
  { kAuth2Cli_VaultNodeRemoved-1, "Auth2Cli VaultNodeRemoved" },
  { kAuth2Cli_VaultNodeRefsFetched-1, "Auth2Cli VaultNodeRefsFetched" },
  { kAuth2Cli_VaultInitAgeReply-1, "Auth2Cli VaultInitAgeReply" },
  { kAuth2Cli_VaultNodeFindReply-1, "Auth2Cli VaultNodeFindReply" },
  { kAuth2Cli_VaultSaveNodeReply-1, "Auth2Cli VaultSaveNodeReply" },
  { kAuth2Cli_VaultAddNodeReply-1, "Auth2Cli VaultAddNodeReply" },
  { kAuth2Cli_VaultRemoveNodeReply-1, "Auth2Cli VaultRemoveNodeReply" },
  { kAuth2Cli_AgeReply-1, "Auth2Cli AgeReply" },
  { kAuth2Cli_FileListReply-1, "Auth2Cli FileListReply" },
  { kAuth2Cli_FileDownloadChunk-1, "Auth2Cli FileDownloadChunk" },
  { kAuth2Cli_PropagateBuffer-1, "Auth2Cli PropagateBuffer" },
  { kAuth2Cli_KickedOff-1, "Auth2Cli KickedOff" },
  { kAuth2Cli_PublicAgeList-1, "Auth2Cli PublicAgeList" },
  { kAuth2Cli_ScoreCreateReply-1, "Auth2Cli ScoreCreateReply" },
  { kAuth2Cli_ScoreDeleteReply-1, "Auth2Cli ScoreDeleteReply" },
  { kAuth2Cli_ScoreGetScoresReply-1, "Auth2Cli ScoreGetScoresReply" },
  { kAuth2Cli_ScoreAddPointsReply-1, "Auth2Cli ScoreAddPointsReply" },
  { kAuth2Cli_ScoreTransferPointsReply-1, "Auth2Cli ScoreTransferPointsReply" },
  { kAuth2Cli_ScoreSetPointsReply-1, "Auth2Cli ScoreSetPointsReply" },
  { kAuth2Cli_ScoreGetRanksReply-1, "Auth2Cli ScoreGetRanksReply" },
  { 0, NULL }
};

static const value_string live_client_gate_msgtypes[] = {
  { kCli2GateKeeper_PingRequest, "Cli2GateKeeper PingRequest" },
  { kCli2GateKeeper_FileSrvIpAddressRequest, "Cli2GateKeeper FileSrvIpAddressRequest" },
  { kCli2GateKeeper_AuthSrvIpAddressRequest, "Cli2GateKeeper AuthSrvIpAddressRequest" },
  { 0, NULL }
};

static const value_string live_server_gate_msgtypes[] = {
  { kGateKeeper2Cli_PingReply, "GateKeeper2Cli PingReply" },
  { kGateKeeper2Cli_FileSrvIpAddressReply, "GateKeeper2Cli FileSrvIpAddressReply" },
  { kGateKeeper2Cli_AuthSrvIpAddressReply, "GateKeeper2Cli AuthSrvIpAddressReply" },
  { 0, NULL }
};

static const value_string live_client_auth_msgtypes[] = {
  { kCli2Auth_PingRequest, "Cli2Auth PingRequest" },
  { kCli2Auth_ClientRegisterRequest, "Cli2Auth ClientRegisterRequest" },
  { kCli2Auth_ClientSetCCRLevel, "Cli2Auth ClientSetCCRLevel" },
  { kCli2Auth_AcctLoginRequest, "Cli2Auth AcctLoginRequest" },
  { kCli2Auth_AcctSetPlayerRequest, "Cli2Auth AcctSetPlayerRequest" },
  { kCli2Auth_AcctCreateRequest, "Cli2Auth AcctCreateRequest" },
  { kCli2Auth_AcctChangePasswordRequest, "Cli2Auth AcctChangePasswordRequest" },
  { kCli2Auth_AcctSetRolesRequest, "Cli2Auth AcctSetRolesRequest" },
  { kCli2Auth_AcctSetBillingTypeRequest, "Cli2Auth AcctSetBillingTypeRequest" },
  { kCli2Auth_AcctActivateRequest, "Cli2Auth AcctActivateRequest" },
  { kCli2Auth_AcctCreateFromKeyRequest, "Cli2Auth AcctCreateFromKeyRequest" },
  { kCli2Auth_PlayerDeleteRequest, "Cli2Auth PlayerDeleteRequest" },
  { kCli2Auth_PlayerCreateRequest, "Cli2Auth PlayerCreateRequest" },
  { kCli2Auth_UpgradeVisitorRequest, "Cli2Auth UpgradeVisitorRequest" },
  { kCli2Auth_SetPlayerBanStatusRequest, "Cli2Auth SetPlayerBanStatusRequest" },
  { kCli2Auth_KickPlayer, "Cli2Auth KickPlayer" },
  { kCli2Auth_ChangePlayerNameRequest, "Cli2Auth ChangePlayerNameRequest" },
  { kCli2Auth_SendFriendInviteRequest, "Cli2Auth SendFriendInviteRequest" },
  { kCli2Auth_VaultNodeCreate, "Cli2Auth VaultNodeCreate" },
  { kCli2Auth_VaultNodeFetch, "Cli2Auth VaultNodeFetch" },
  { kCli2Auth_VaultNodeSave, "Cli2Auth VaultNodeSave" },
  { kCli2Auth_VaultNodeAdd, "Cli2Auth VaultNodeAdd" },
  { kCli2Auth_VaultNodeRemove, "Cli2Auth VaultNodeRemove" },
  { kCli2Auth_VaultFetchNodeRefs, "Cli2Auth VaultFetchNodeRefs" },
  { kCli2Auth_VaultInitAgeRequest, "Cli2Auth VaultInitAgeRequest" },
  { kCli2Auth_VaultNodeFind, "Cli2Auth VaultNodeFind" },
  { kCli2Auth_VaultSetSeen, "Cli2Auth VaultSetSeen" },
  { kCli2Auth_VaultSendNode, "Cli2Auth VaultSendNode" },
  { kCli2Auth_AgeRequest, "Cli2Auth AgeRequest" },
  { kCli2Auth_FileListRequest, "Cli2Auth FileListRequest" },
  { kCli2Auth_FileDownloadRequest, "Cli2Auth FileDownloadRequest" },
  { kCli2Auth_FileDownloadChunkAck, "Cli2Auth FileDownloadChunkAck" },
  { kCli2Auth_PropagateBuffer, "Cli2Auth PropagateBuffer" },
  { kCli2Auth_GetPublicAgeList, "Cli2Auth GetPublicAgeList" },
  { kCli2Auth_SetAgePublic, "Cli2Auth SetAgePublic" },
  { kCli2Auth_LogPythonTraceback, "Cli2Auth LogPythonTraceback" },
  { kCli2Auth_LogStackDump, "Cli2Auth LogStackDump" },
  { kCli2Auth_LogClientDebuggerConnect, "Cli2Auth LogClientDebuggerConnect" },
  { kCli2Auth_ScoreCreate, "Cli2Auth ScoreCreate" },
  { kCli2Auth_ScoreDelete, "Cli2Auth ScoreDelete" },
  { kCli2Auth_ScoreGetScores, "Cli2Auth ScoreGetScores" },
  { kCli2Auth_ScoreAddPoints, "Cli2Auth ScoreAddPoints" },
  { kCli2Auth_ScoreTransferPoints, "Cli2Auth ScoreTransferPoints" },
  { kCli2Auth_ScoreSetPoints, "Cli2Auth ScoreSetPoints" },
  { kCli2Auth_ScoreGetRanks, "Cli2Auth ScoreGetRanks" },
  { 0, NULL }
};

static const value_string live_server_auth_msgtypes[] = {
  { kAuth2Cli_PingReply, "Auth2Cli PingReply" },
  { kAuth2Cli_ServerAddr, "Auth2Cli ServerAddr" },
  { kAuth2Cli_NotifyNewBuild, "Auth2Cli NotifyNewBuild" },
  { kAuth2Cli_ClientRegisterReply, "Auth2Cli ClientRegisterReply" },
  { kAuth2Cli_AcctLoginReply, "Auth2Cli AcctLoginReply" },
  { kAuth2Cli_AcctPlayerInfo, "Auth2Cli AcctPlayerInfo" },
  { kAuth2Cli_AcctSetPlayerReply, "Auth2Cli AcctSetPlayerReply" },
  { kAuth2Cli_AcctCreateReply, "Auth2Cli AcctCreateReply" },
  { kAuth2Cli_AcctChangePasswordReply, "Auth2Cli AcctChangePasswordReply" },
  { kAuth2Cli_AcctSetRolesReply, "Auth2Cli AcctSetRolesReply" },
  { kAuth2Cli_AcctSetBillingTypeReply, "Auth2Cli AcctSetBillingTypeReply" },
  { kAuth2Cli_AcctActivateReply, "Auth2Cli AcctActivateReply" },
  { kAuth2Cli_AcctCreateFromKeyReply, "Auth2Cli AcctCreateFromKeyReply" },
  { kAuth2Cli_PlayerCreateReply, "Auth2Cli PlayerCreateReply" },
  { kAuth2Cli_PlayerDeleteReply, "Auth2Cli PlayerDeleteReply" },
  { kAuth2Cli_UpgradeVisitorReply, "Auth2Cli UpgradeVisitorReply" },
  { kAuth2Cli_SetPlayerBanStatusReply, "Auth2Cli SetPlayerBanStatusReply" },
  { kAuth2Cli_ChangePlayerNameReply, "Auth2Cli ChangePlayerNameReply" },
  { kAuth2Cli_SendFriendInviteReply, "Auth2Cli SendFriendInviteReply" },
  { kAuth2Cli_VaultNodeCreated, "Auth2Cli VaultNodeCreated" },
  { kAuth2Cli_VaultNodeFetched, "Auth2Cli VaultNodeFetched" },
  { kAuth2Cli_VaultNodeChanged, "Auth2Cli VaultNodeChanged" },
  { kAuth2Cli_VaultNodeDeleted, "Auth2Cli VaultNodeDeleted" },
  { kAuth2Cli_VaultNodeAdded, "Auth2Cli VaultNodeAdded" },
  { kAuth2Cli_VaultNodeRemoved, "Auth2Cli VaultNodeRemoved" },
  { kAuth2Cli_VaultNodeRefsFetched, "Auth2Cli VaultNodeRefsFetched" },
  { kAuth2Cli_VaultInitAgeReply, "Auth2Cli VaultInitAgeReply" },
  { kAuth2Cli_VaultNodeFindReply, "Auth2Cli VaultNodeFindReply" },
  { kAuth2Cli_VaultSaveNodeReply, "Auth2Cli VaultSaveNodeReply" },
  { kAuth2Cli_VaultAddNodeReply, "Auth2Cli VaultAddNodeReply" },
  { kAuth2Cli_VaultRemoveNodeReply, "Auth2Cli VaultRemoveNodeReply" },
  { kAuth2Cli_AgeReply, "Auth2Cli AgeReply" },
  { kAuth2Cli_FileListReply, "Auth2Cli FileListReply" },
  { kAuth2Cli_FileDownloadChunk, "Auth2Cli FileDownloadChunk" },
  { kAuth2Cli_PropagateBuffer, "Auth2Cli PropagateBuffer" },
  { kAuth2Cli_KickedOff, "Auth2Cli KickedOff" },
  { kAuth2Cli_PublicAgeList, "Auth2Cli PublicAgeList" },
  { kAuth2Cli_ScoreCreateReply, "Auth2Cli ScoreCreateReply" },
  { kAuth2Cli_ScoreDeleteReply, "Auth2Cli ScoreDeleteReply" },
  { kAuth2Cli_ScoreGetScoresReply, "Auth2Cli ScoreGetScoresReply" },
  { kAuth2Cli_ScoreAddPointsReply, "Auth2Cli ScoreAddPointsReply" },
  { kAuth2Cli_ScoreTransferPointsReply, "Auth2Cli ScoreTransferPointsReply" },
  { kAuth2Cli_ScoreSetPointsReply, "Auth2Cli ScoreSetPointsReply" },
  { kAuth2Cli_ScoreGetRanksReply, "Auth2Cli ScoreGetRanksReply" },
  { 0, NULL }
};

static const value_string live_client_game_msgtypes[] = {
  { kCli2Game_PingRequest, "Cli2Game PingRequest" },
  { kCli2Game_JoinAgeRequest, "Cli2Game JoinAgeRequest" },
  { kCli2Game_PropagateBuffer, "Cli2Game PropagateBuffer" },
  { kCli2Game_GameMgrMsg, "Cli2Game GameMgrMsg" },
  { 0, NULL }
};

static const value_string live_server_game_msgtypes[] = {
  { kGame2Cli_PingReply, "Game2Cli PingReply" },
  { kGame2Cli_JoinAgeReply, "Game2Cli JoinAgeReply" },
  { kGame2Cli_PropagateBuffer, "Game2Cli PropagateBuffer" },
  { kGame2Cli_GameMgrMsg, "Game2Cli GameMgrMsg" },
  { 0, NULL }
};

#define ManifestRequestTrans 0x14
#define DownloadRequestTrans 0x15
#define FileRcvdFileDownloadChunkTrans 0x17
#define PingRequestTrans 0x00
#define FileRcvdFileManifestChunkTrans 0x16 /* name made up */

static const value_string file_transactions[] = {
  { ManifestRequestTrans, "ManifestRequestTrans" },
  { DownloadRequestTrans, "DownloadRequestTrans" },
  { FileRcvdFileDownloadChunkTrans, "FileRcvdFileDownloadChunkTrans" },
  { FileRcvdFileManifestChunkTrans, "FileRcvdFileManifestChunkTrans" },
  { PingRequestTrans, "PingRequestTrans" },
  { 0, NULL }
};

static const value_string error_messages[] = {
  { 0, "kNetSuccess: No error" },
  { 1, "kNetErrInternalError: Internal Error" },
  { 2, "kNetErrTimeout: No Response From Server" },
  { 3, "kNetErrBadServerData: Invalid Server Data" },
  { 4, "kNetErrAgeNotFound: Age Not Found" },
  { 5, "kNetErrConnectFailed: Unable to connect to Myst Online." },
  { 6, "kNetErrDisconnected: Disconnected from Myst Online." },
  { 7, "kNetErrFileNotFound: File Not Found" },
  { 8, "kNetErrOldBuildId: Old Build" },
  { 9, "kNetErrRemoteShutdown: Remote Shutdown" },
  { 10, "kNetErrTimeoutOdbc: Database Timeout" },
  { 11, "kNetErrAccountAlreadyExists: Account Already Exists" },
  { 12, "kNetErrPlayerAlreadyExist: Player Already Exists" },
  { 13, "kNetErrAccountNotFound: Account Not Found." },
  { 14, "kNetErrPlayerNotFound: Player Not Found" },
  { 15, "kNetErrInvalidParameter: Invalid Parameter" },
  { 16, "kNetErrNameLookupFailed: Name Lookup Failed" },
  { 17, "kNetErrLoggedInElsewhere: Logged In Elsewhere" },
  { 18, "kNetErrVaultNodeNotFound: Vault Node Not Found" },
  { 19, "kNetErrMaxPlayersOnAcct: Max Players On Account" },
  { 20, "kNetErrAuthenticationFailed: Incorrect password.\nMake sure CAPS LOCK is not on." },
  { 21, "kNetErrStateObjectNotFound: State Object Not Found" },
  { 22, "kNetErrLoginDenied: Login Denied" },
  { 23, "kNetErrCircularReference: Circular Reference" },
  { 24, "kNetErrAccountNotActivated: Account Not Activated." },
  { 25, "kNetErrKeyAlreadyUsed: Key Already Used" },
  { 26, "kNetErrKeyNotFound: Key Not Found" },
  { 27, "kNetErrActivationCodeNotFound: Activation Code Not Found" },
  { 28, "kNetErrPlayerNameInvalid: Player Name Invalid" },
  { 29, "kNetErrNotSupported: Not Supported" },
  { 30, "kNetErrServiceForbidden: Service Forbidden" },
  { 31, "kNetErrAuthTokenTooOld: Auth Token Too Old" },
  { 32, "kNetErrMustUseGameTapClient: Must Use GameTap Client" },
  { 33, "kNetErrTooManyFailedLogins: Too Many Failed Logins" },
  { 34, "kNetErrGameTapConnectionFailed: Unable to connect to GameTap, please try again in a few minutes." },
  { 35, "kNetErrGTTooManyAuthOptions: GameTap: Too Many Auth Options" },
  { 36, "kNetErrGTMissingParameter: GameTap: Missing Parameter" },
  { 37, "kNetErrGTServerError: Unable to connect to GameTap, please try again in a few minutes." },
  { 38, "kNetErrAccountBanned: Your account has been banned from accessing Myst Online.  If you are unsure as to why this happened please contact customer support." },
  { 39, "kNetErrKickedByCCR: Account kicked by CCR" },
  { 40, "Wrong score type for operation" },
  { 41, "Not enough points" },
  { 42, "Non-fixed score already exists" },
  { 43, "No score data found" },
  { 44, "Invite: Couldn't find player" },
  { 45, "Invite: Too many hoods" },
  { -1, "kNetPending: Pending" },
  { 0, NULL }
};

static const value_string avatar_types[] = {
  { 0x0, "Visitor" },
  { 0x1, "Explorer" },
  { 0, NULL }
};

static const value_string login_flags[] = {
  /* { 0x0, "Visitor/MOULa" }, */
  { 0x0, "No result" },
  { 0x1, "Explorer/MOULa" },
  { 0x2, "Visitor/MOUL" },
  { 0x3, "Explorer/MOUL" },
  { 0, NULL }
};

#define kIndividual 0x00
#define kNeighborhood 0x01

static const value_string score_rankgroups[] = {
  { kIndividual, "kIndividual" },
  { kNeighborhood, "kNeighborhood" },
  { 0, NULL }
};

#define kOverall 0x00
#define kYear 0x01
#define kMonth 0x02
#define kDay 0x03

static const value_string score_timeperiods[] = {
  { kOverall, "kOverall" },
  { kYear, "kYear" },
  { kMonth, "kMonth" },
  { kDay, "kDay" },
  { 0, NULL }
};

#define kFixed 0x00
#define kAccumulative 0x01
#define kAccumAllowNegative 0x02

static const value_string score_types[] = {
  { kFixed, "kFixed" },
  { kAccumulative, "kAccumulative" },
  { kAccumAllowNegative, "kAccumAllowNegative" },
  { 0, NULL }
};

enum game_types {
  Unknown_pfGmType = 0,
  pfGmMarker = 0x000b2c39, /* 000b2c39-0319-4be1-b06c-7a105b160fcf */
  pfGmHeek = 0x9d83c2e2, /* 9d83c2e2-7835-4477-9aaa-22254c59a753 */
  pfGmBlueSpiral = 0x5ff98165, /* 5ff98165-913e-4fd1-a2c2-9c7f31be2cc8 */
  pfGmVarSync = 0x475c2e9b, /* 475c2e9b-a245-4106-a047-9b25d41ff333 */
  pfGmClimbingWall = 0x6224cdf4, /* 6224cdf4-3556-4740-b7cd-d637562d07be */
  pfGmTicTacToe = 0xa7236529 /* a7236529-11d8-4758-9368-59cb43445a83 */
};

static const value_string gamemgr_uuids[] = {
  { Unknown_pfGmType, "Unknown" },
  { pfGmMarker, "Marker" },
  { pfGmHeek, "Heek" },
  { pfGmBlueSpiral, "BlueSpiral" },
  { pfGmVarSync, "VarSync" },
  { pfGmClimbingWall, "ClimbingWall" },
  { pfGmTicTacToe, "TicTacToe" },
  { 0, NULL }
};

/* Server to client game manager messages.  From PlasmaGameConstants.py */

#define kGameCliPlayerJoinedMsg 0x00
#define kGameCliPlayerLeftMsg 0x01
#define kGameCliInviteFailedMsg 0x02
#define kGameCliOwnerChangeMsg 0x03

#define kGameCliTTTMsg 0x04
#define kGameCliHeekMsg 0x05
#define kGameCliMarkerMsg 0x06
#define kGameCliBlueSpiralMsg 0x07
#define kGameCliClimbingWallMsg 0x08
#define kGameCliVarSyncMsg 0x09

static const value_string gamecli_msgtypes[] = {
  { kGameCliPlayerJoinedMsg, "kGameCliPlayerJoinedMsg" },
  { kGameCliPlayerLeftMsg, "kGameCliPlayerLeftMsg" },
  { kGameCliInviteFailedMsg, "kGameCliInviteFailedMsg" },
  { kGameCliOwnerChangeMsg, "kGameCliOwnerChangeMsg" },
  { kGameCliTTTMsg, "kGameCliTTTMsg" },
  { kGameCliHeekMsg, "kGameCliHeekMsg" },
  { kGameCliMarkerMsg, "kGameCliMarkerMsg" },
  { kGameCliBlueSpiralMsg, "kGameCliBlueSpiralMsg" },
  { kGameCliClimbingWallMsg, "kGameCliClimbingWallMsg" },
  { kGameCliVarSyncMsg, "kGameCliVarSyncMsg" },
  { 0, NULL }
};

#define kVarSyncStringVarChanged 0x04
#define kVarSyncNumericVarChanged 0x05
#define kVarSyncAllVarsSent 0x06
#define kVarSyncStringVarCreated 0x07
#define kVarSyncNumericVarCreated 0x08

static const value_string varsync_msgtypes[] = {
  { kVarSyncStringVarChanged, "kVarSyncStringVarChanged" },
  { kVarSyncNumericVarChanged, "kVarSyncNumericVarChanged" },
  { kVarSyncAllVarsSent, "kVarSyncAllVarsSent" },
  { kVarSyncStringVarCreated, "kVarSyncStringVarCreated" },
  { kVarSyncNumericVarCreated, "kVarSyncNumericVarCreated" },
  { 0, NULL }
};

#define kBlueSpiralClothOrder 0x04
#define kBlueSpiralSuccessfulHit 0x05
#define kBlueSpiralGameWon 0x06
#define kBlueSpiralGameOver 0x07
#define kBlueSpiralGameStarted 0x08

static const value_string bluespiral_msgtypes[] = {
  { kBlueSpiralClothOrder, "kBlueSpiralClothOrder" },
  { kBlueSpiralSuccessfulHit, "kBlueSpiralSuccessfulHit" },
  { kBlueSpiralGameWon, "kBlueSpiralGameWon" },
  { kBlueSpiralGameOver, "kBlueSpiralGameOver" },
  { kBlueSpiralGameStarted, "kBlueSpiralGameStarted" },
  { 0, NULL }
};

#define kClimbingWallNumBlockersChanged 0x04
#define kClimbingWallReadyMsg 0x05
#define kClimbingWallBlockersChanged 0x06
#define kClimbingWallPlayerEntered 0x07
#define kClimbingWallSuitMachineLocked 0x08
#define kClimbingWallGameOver 0x09

static const value_string climbingwall_msgtypes[] = {
  { kClimbingWallNumBlockersChanged, "kClimbingWallNumBlockersChanged" },
  { kClimbingWallReadyMsg, "kClimbingWallReadyMsg" },
  { kClimbingWallBlockersChanged, "kClimbingWallBlockersChanged" },
  { kClimbingWallPlayerEntered, "kClimbingWallPlayerEntered" },
  { kClimbingWallSuitMachineLocked, "kClimbingWallSuitMachineLocked" },
  { kClimbingWallGameOver, "kClimbingWallGameOver"},
  { 0, NULL }
};

    #define kClimbingWallReadyNumBlockers 0x00
    #define kClimbingWallReadyBlockers 0x01

    static const value_string climbingwallready_types[] = {
      { kClimbingWallReadyNumBlockers, "kClimbingWallReadyNumBlockers" },
      { kClimbingWallReadyBlockers, "kClimbingWallReadyBlockers" },
      { 0, NULL }
    };

#define kGameMgrInviteReceivedMsg 0x01
#define kGameMgrInviteRevokedMsg 0x02

static const value_string gamemgr_msgtypes[] = {
  { kGameMgrInviteReceivedMsg, "kGameMgrInviteReceivedMsg" },
  { kGameMgrInviteRevokedMsg, "kGameMgrInviteRevokedMsg" },
  { 0, NULL }
};

    #define kGameInviteSuccess 0x00
    #define kGameInviteErrNotOwner 0x01
    #define kGameInviteErrAlreadyInvited 0x02
    #define kGameInviteErrAlreadyJoined 0x03
    #define kGameInviteErrGameStarted 0x04
    #define kGameInviteErrGameOver 0x05
    #define kGameInviteErrGameFull 0x06
    #define kGameInviteErrNoJoin 0x07

    static const value_string gamecli_invite_errors[] = {
      { kGameInviteSuccess, "kGameInviteSuccess" },
      { kGameInviteErrNotOwner, "kGameInviteErrNotOwner" },
      { kGameInviteErrAlreadyInvited, "kGameInviteErrAlreadyInvited" },
      { kGameInviteErrAlreadyJoined, "kGameInviteErrAlreadyJoined" },
      { kGameInviteErrGameStarted, "kGameInviteErrGameStarted" },
      { kGameInviteErrGameOver, "kGameInviteErrGameOver" },
      { kGameInviteErrGameFull, "kGameInviteErrGameFull" },
      { kGameInviteErrNoJoin, "kGameInviteErrNoJoin" },
      { 0, NULL }
    };

#define kHeekPlayGame 0x04
#define kHeekGoodbye 0x05
#define kHeekWelcome 0x06
#define kHeekDrop 0x07
#define kHeekSetup 0x08
#define kHeekLightState 0x09
#define kHeekInterfaceState 0x0a
#define kHeekCountdownState 0x0b
#define kHeekWinLose 0x0c
#define kHeekGameWin 0x0d
#define kHeekPointUpdate 0x0e

static const value_string heek_msgtypes[] = {
  { kHeekPlayGame, "kHeekPlayGame" },
  { kHeekGoodbye, "kHeekGoodbye" },
  { kHeekWelcome, "kHeekWelcome" },
  { kHeekDrop, "kHeekDrop" },
  { kHeekSetup, "kHeekSetup" },
  { kHeekLightState, "kHeekLightState" },
  { kHeekInterfaceState, "kHeekInterfaceState" },
  { kHeekCountdownState, "kHeekCountdownState" },
  { kHeekWinLose, "kHeekWinLose" },
  { kHeekGameWin, "kHeekGameWin" },
  { kHeekPointUpdate, "kHeekPointUpdate" },
  { 0, NULL }
};

    #define kHeekCountdownStart 0x00
    #define kHeekCountdownStop 0x01
    #define kHeekCountdownIdle 0x02

    static const value_string heek_countdown_states[] = {
      { kHeekCountdownStart, "kHeekCountdownStart" },
      { kHeekCountdownStop, "kHeekCountdownStop" },
      { kHeekCountdownIdle, "kHeekCountdownIdle" },
      { 0, NULL }
    };

    #define kHeekGameChoiceRock 0x00
    #define kHeekGameChoicePaper 0x01
    #define kHeekGameChoiceScissors 0x02

    static const value_string heek_game_choice[] = {
      { kHeekGameChoiceRock, "kHeekGameChoiceRock" },
      { kHeekGameChoicePaper, "kHeekGameChoicePaper" },
      { kHeekGameChoiceScissors, "kHeekGameChoiceScissors" },
      { 0, NULL }
    };

    #define kHeekGameSeqCountdown 0x00
    #define kHeekGameSeqChoiceAnim 0x01
    #define kHeekGameSeqGameWinAnim 0x02

    static const value_string heek_game_seq[] = {
      { kHeekGameSeqCountdown, "kHeekGameSeqCountdown" },
      { kHeekGameSeqChoiceAnim, "kHeekGameSeqChoiceAnim" },
      { kHeekGameSeqGameWinAnim, "kHeekGameSeqGameWinAnim" },
      { 0, NULL }
    };

    #define kHeekLightOn 0x00
    #define kHeekLightOff 0x01
    #define kHeekLightFlash 0x02

    static const value_string heek_light_states[] = {
      { kHeekLightOn, "kHeekLightOn" },
      { kHeekLightOff, "kHeekLightOff" },
      { kHeekLightFlash, "kHeekLightFlash" },
      { 0, NULL }
    };

    static const value_string heek_light_values[] = {
      { 0, "Blue 1 [Rock]" },
      { 1, "Blue 2 [Rock]" },
      { 2, "Green 1 [Paper]" },
      { 3, "Green 2 [Paper]" },
      { 4, "Red 1 [Scissors]" },
      { 5, "Red 2 [Scissors]" },
      { 0, NULL }
    };

#define kMarkerTemplateCreated 0x04
#define kMarkerTeamAssigned 0x05
#define kMarkerGameType 0x06
#define kMarkerGameStarted 0x07
#define kMarkerGamePaused 0x08
#define kMarkerGameReset 0x09
#define kMarkerGameOver 0x0a
#define kMarkerGameNameChanged 0x0b
#define kMarkerTimeLimitChanged 0x0c
#define kMarkerGameDeleted 0x0d
#define kMarkerMarkerAdded 0x0e
#define kMarkerMarkerDeleted 0x0f
#define kMarkerMarkerNameChanged 0x10
#define kMarkerMarkerCaptured 0x11

static const value_string marker_msgtypes[] = {
  { kMarkerTemplateCreated, "kMarkerTemplateCreated" },
  { kMarkerTeamAssigned, "kMarkerTeamAssigned" },
  { kMarkerGameType, "kMarkerGameType" },
  { kMarkerGameStarted, "kMarkerGameStarted" },
  { kMarkerGamePaused, "kMarkerGamePaused" },
  { kMarkerGameReset, "kMarkerGameReset" },
  { kMarkerGameOver, "kMarkerGameOver" },
  { kMarkerGameNameChanged, "kMarkerGameNameChanged" },
  { kMarkerTimeLimitChanged, "kMarkerTimeLimitChanged" },
  { kMarkerGameDeleted, "kMarkerGameDeleted" },
  { kMarkerMarkerAdded, "kMarkerMarkerAdded" },
  { kMarkerMarkerDeleted, "kMarkerMarkerDeleted" },
  { kMarkerMarkerNameChanged, "kMarkerMarkerNameChanged" },
  { kMarkerMarkerCaptured, "kMarkerMarkerCaptured" },
  { 0, NULL }
};

    #define kMarkerGameQuest 0x00
    #define kMarkerGameCGZ 0x01
    #define kMarkerGameCapture 0x02
    #define kMarkerGameCaptureAndHold 0x03

    static const value_string marker_gametypes[] = {
      { kMarkerGameQuest, "kMarkerGameQuest" },
      { kMarkerGameCGZ, "kMarkerGameCGZ" },
      { kMarkerGameCapture, "kMarkerGameCapture" },
      { kMarkerGameCaptureAndHold, "kMarkerGameCaptureAndHold" },
      { -1, "Unknown" },
      { 0, NULL }
    };

    /* These are backwards from PlasmaConstants.py */

    #define kMarkerNotCaptured 0x00 /* name made up */
    #define kMarkerCaptured 0x01

    static const value_string marker_captured[] = {
      { kMarkerCaptured, "kMarkerCaptured" },
      { kMarkerNotCaptured, "kMarkerNotCaptured" },
      { 0, NULL }
    };

#define kTTTGameStarted 0x04
#define kTTTGameOver 0x05
#define kTTTMoveMade 0x06

static const value_string ttt_msgtypes[] = {
  { kTTTGameStarted, "kTTTGameStarted" },
  { kTTTGameOver, "kTTTGameOver" },
  { kTTTMoveMade, "kTTTMoveMade" },
  { 0, NULL }
};

    #define kTTTGameResultWinner 0x00
    #define kTTTGameResultTied 0x01
    #define kTTTGameResultGave 0x02
    #define kTTTGameResultError 0x03

    static const value_string ttt_gameresult[] = {
      { kTTTGameResultWinner, "kTTTGameResultWinner" },
      { kTTTGameResultTied, "kTTTGameResultTied" },
      { kTTTGameResultGave, "kTTTGameResultGave" },
      { kTTTGameResultError, "kTTTGameResultError" },
      { 0, NULL }
    };

/* Client to server game manager messages.  These names are made up */

#define kVarSyncNumericVarChange 0x04
#define kVarSyncNumericVarCreate 0x07

static const value_string varsync_climsgtypes[] = {
  { kVarSyncNumericVarChange, "kVarSyncNumericVarChange" },
  { kVarSyncNumericVarCreate, "kVarSyncNumericVarCreate" },
  { 0, NULL }
};

#define kBlueSpiralGameStart 0x03
#define kBlueSpiralClothHit 0x04

static const value_string bluespiral_climsgtypes[] = {
  { kBlueSpiralGameStart, "kBlueSpiralGameStart" },
  { kBlueSpiralClothHit, "kBlueSpiralClothHit" },
  { 0, NULL }
};

#define kMarkerGameStart 0x03
#define kMarkerGamePause 0x04
#define kMarkerGameResetReq 0x05
#define kMarkerGameNameChange 0x06
#define kMarkerTimeLimitChange 0x07  /* no sample - a guess here */
#define kMarkerGameDelete 0x08
#define kMarkerMarkerAdd 0x09
#define kMarkerMarkerDelete 0x0a
#define kMarkerMarkerNameChange 0x0b
#define kMarkerMarkerCapture 0x0c

static const value_string marker_climsgtypes[] = {
  { kMarkerGameStart, "kMarkerGameStart" },
  { kMarkerGamePause, "kMarkerGamePause" },
  { kMarkerGameResetReq, "kMarkerGameResetReq" },
  { kMarkerGameNameChange, "kMarkerGameNameChange" },
  { kMarkerTimeLimitChange, "kMarkerTimeLimitChange" },
  { kMarkerGameDelete, "kMarkerGameDelete" },
  { kMarkerMarkerAdd, "kMarkerMarkerAdd" },
  { kMarkerMarkerDelete, "kMarkerMarkerDelete" },
  { kMarkerMarkerNameChange, "kMarkerMarkerNameChange" },
  { kMarkerMarkerCapture, "kMarkerMarkerCapture" },
  { 0, NULL }
};

#define kHeekPlayGameReq 0x03
#define kHeekGoodbyeReq 0x04
#define kHeekChoice 0x05
#define kHeekAnimationFinished 0x06

static const value_string heek_climsgtypes[] = {
  { kHeekPlayGameReq, "kHeekPlayGameReq" },
  { kHeekGoodbyeReq, "kHeekGoodbyeReq" },
  { kHeekChoice, "kHeekChoice" },
  { kHeekAnimationFinished, "kHeekAnimationFinished" },
  { 0, NULL }
};


/* Vault node content flags - VaultNodeFetched */

#define kNodeId 0x01
#define kCreateTime 0x02
#define kModifyTime 0x04
#define kCreateAgeName 0x08
#define kCreateAgeUuid 0x10
#define kCreatorAcct 0x20
#define kCreatorId 0x40
#define kNodeType 0x80
#define kInt32_1 0x100
#define kInt32_2 0x200
#define kInt32_3 0x400
#define kInt32_4 0x800
#define kUInt32_1 0x1000
#define kUInt32_2 0x2000
#define kUInt32_3 0x4000
#define kUInt32_4 0x8000
#define kUuid_1 0x10000
#define kUuid_2 0x20000
#define kUuid_3 0x40000
#define kUuid_4 0x80000
#define kString64_1 0x100000
#define kString64_2 0x200000
#define kString64_3 0x400000
#define kString64_4 0x800000
#define kString64_5 0x1000000
#define kString64_6 0x2000000
#define kIString64_1 0x4000000
#define kIString64_2 0x8000000
#define kText_1 0x10000000
#define kText_2 0x20000000
#define kBlob_1 0x40000000
#define kBlob_2 0x80000000

static hf_register_info hf_live[] = {
  { &hf_urulive_msgtype_client_v1,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_client_msgtypes_v1), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_server_v1,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_server_msgtypes_v1), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_auth_client8,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_client_auth_msgtypes8), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_auth_server8,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_server_auth_msgtypes8), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_gate_client,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_client_gate_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_gate_server,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_server_gate_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_auth_client,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_client_auth_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_auth_server,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_server_auth_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_game_client,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_client_game_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_msgtype_game_server,
    { "Message type", "uru.live.msgtype",
      FT_UINT16, BASE_HEX, VALS(live_server_game_msgtypes), 0x0,
      "Which kind of message this is", HFILL }
  },
  { &hf_urulive_cmd,
    { "Command", "uru.live.cmd",
      FT_UINT32, BASE_HEX, VALS(live_typecodes), 0x0,
      "Which kind of NetMsg this is", HFILL }
  },
  { &hf_urulive_cmd2,
    { "Command", "uru.live.cmd",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "Which kind of NetMsg this is", HFILL }
  },
  { &hf_urulive_msglen,
    { "Message length", "uru.live.size",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "The length of the message (not the packet)", HFILL }
  },
  { &hf_urulive_encrypted,
    { "Encrypted data", "uru.live.encrypted",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Un-decrypted data (key unknown or decryption disabled)", HFILL }
  },

  { &hf_urulive_result,
    { "Result", "uru.live.result",
      FT_UINT32, BASE_DEC, VALS(error_messages), 0x0,
      "", HFILL }
  },

  /* the first message(s) to each server */
  { &hf_urulive_nego_type,
    { "Message", "uru.live.nego.type",
      FT_UINT8, BASE_HEX, VALS(live_negotypes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_len,
    { "Length", "uru.live.nego.len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_unk0,
    { "Unknown", "uru.live.nego.unk0",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_ver,
    { "Client version", "uru.live.nego.version",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_unk32,
    { "Unknown", "uru.live.nego.unk32",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_release,
    { "Release number", "uru.live.nego.release",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_idstring,
    { "Client UUID", "uru.live.nego.idstring",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_datalen,
    { "Length of data", "uru.live.nego.datalen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_data,
    { "Unknown data", "uru.live.nego.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_nonce,
    { "Nonce", "uru.live.nego.nonce",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_nego_reply,
    { "Server reply", "uru.live.nego.reply",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },

  /* client<->auth messages */
  { &hf_urulive_reqid,
    {"Request identifier", "uru.live.reqid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_register_ver,
    { "Client version", "uru.live.register.version",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_register_reply,
    { "Server reply", "uru.live.register.reply",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_ping_id,
    { "Ping unique ID", "uru.live.ping.id",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_ping_unk1,
    { "Unknown (zeros)", "uru.live.ping.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_ping_unk2,
    { "Unknown (zeros)", "uru.live.ping.unk2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gate_unk0,
    { "Unknown","uru.live.gate.unk0",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gate_addr,
    { "Server address","uru.live.gate.addr",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_addr_ip,
    { "SrvAuth address","uru.live.addr.ip",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_addr_uuid,
    { "UUID", "uru.live.addr.uuid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_fname,
    { "Age filename", "uru.live.age.fname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_UUID,
    { "Age UUID", "uru.live.age.UUID",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_unk1,
    {"Unknown (zeros)", "uru.live.age.unk1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_id,
    {"Server identifier", "uru.live.age.id",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_nodeid,
    {"Age Node ID", "uru.live.age.nodeid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_addr,
    { "Age game server IP address","uru.live.age.addr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_iname,
    { "Instance name", "uru.live.age.iname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_uname,
    { "User defined name", "uru.live.age.uname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_dname,
    { "Display name", "uru.live.age.dname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_parentid,
    { "Parent age UUID", "uru.live.age.parentid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_mgr,
    { "Age Mgr Node", "uru.live.age.mgr",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_info,
    { "Age Info Node", "uru.live.age.info",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_inum,
    { "Instance number", "uru.live.age.inum",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_public,
    { "Public", "uru.live.age.public",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "", HFILL }
  },
  { &hf_urulive_age_public32,
    { "Public", "uru.live.age.public",
      FT_BOOLEAN, 32, TFS(&yes_no), 0x0,
      "", HFILL }
  },
  { &hf_urulive_pubage_unk0,
    { "Unknown", "uru.live.pubage.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_pubage_ct,
    { "Instance count", "uru.live.pubage.ct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_pubage_unk1,
    { "Unknown (-1)", "uru.live.pubage.unk1",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_pubage_owners,
    { "Number of owners", "uru.live.pubage.owners",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_pubage_pop,
    { "Population", "uru.live.pubage.pop",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_unk0,
    { "Unknown", "uru.live.login.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_name,
    { "Login name", "uru.live.login.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_hash,
    { "Hash", "uru.live.login.hash",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_token,
    { "Auth token", "uru.live.login.token",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_os,
    { "OS", "uru.live.login.os",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_acct,
    { "Account ID", "uru.live.login.acct",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_unk8,
    { "Unknown", "uru.live.login.unk8",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_flags,
    { "Flags", "uru.live.login.flags",
      FT_UINT32, BASE_HEX, VALS(login_flags), 0x0,
      "", HFILL }
  },
  { &hf_urulive_login_key,
    { "Key", "uru.live.login.key",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_plist_ki,
    { "KI number", "uru.live.plist.ki",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_plist_name,
    { "Avatar name", "uru.live.plist.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_plist_gender,
    { "Gender", "uru.live.plist.gender",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_plist_type,
    { "Avatar type", "uru.live.plist.type",
      FT_UINT32, BASE_DEC, VALS(avatar_types), 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_unk0,
    { "Unknown (zeros)", "uru.live.file.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_dir,
    { "Directory", "uru.live.file.list.dir",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_suffix,
    { "Suffix", "uru.live.file.list.suffix",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_len,
    { "Message length", "uru.live.file.list.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_file,
    { "File", "uru.live.file.list.file",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_fname,
    { "File name", "uru.live.file.list.fname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_list_flen,
    { "File length", "uru.live.file.list.flen",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_get_file,
    { "File name", "uru.live.file.get.file",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_get_len,
    { "Total file length", "uru.live.file.get.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_get_offset,
    { "Offset of this part", "uru.live.file.get.offset",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_get_thislen,
    { "Part of file in this message", "uru.live.file.get.thislen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_get_data,
    { "File data", "uru.live.file.get.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_msglen,
    { "Message length", "uru.live.file.msglen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_trans,
    { "Transaction type", "uru.live.file.trans",
      FT_UINT32, BASE_HEX, VALS(file_transactions), 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_unknum,
    { "Unknown (chunk-related number?)", "uru.live.file.unknum",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mname,
    { "Manifest name", "uru.live.file.mname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_fname,
    { "File name", "uru.live.file.fname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_buf,
    { "Garbage in a buffer", "uru.live.file.buf",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mct,
    { "Number of files in manifest", "uru.live.file.mct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mlen,
    { "Message length", "uru.live.file.mlen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mfile,
    { "File name", "uru.live.file.munk",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mpath,
    { "Full path", "uru.live.file.mpath",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_muncsum,
    { "Uncompressed checksum", "uru.live.file.muncsum",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mcsum,
    { "Compressed checksum", "uru.live.file.mcsum",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_munclen,
    { "Uncompressed file length", "uru.live.file.munclen",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mclen,
    { "Compressed file length", "uru.live.file.mclen",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mterm, /* empty-string terminated arrays of strings... */
    { "Empty string", "uru.live.file.mterm",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_mflags,
    { "File flags", "uru.live.file.mflags",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "File type flags", HFILL }
  },
  { &hf_urulive_file_mflags_sc,
    { "L - R StreamingCache files", "uru.live.file.mflags.sc",
      FT_BOOLEAN, 32, NULL, 0x00000001,
      "use L - R streamingCache files", HFILL }
  },
  { &hf_urulive_file_mflags_of,
    { "ogg files", "uru.live.file.mflags.of",
      FT_BOOLEAN, 32, NULL, 0x00000002,
      "use original file", HFILL }
  },
  { &hf_urulive_file_mflags_sf,
    { "use single streamingCache file", "uru.live.file.mflags.sf",
      FT_BOOLEAN, 32, NULL, 0x00000004,
      "use single streamingCache file", HFILL }
  },
  { &hf_urulive_file_flen,
    { "File length", "uru.live.file.flen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_thislen,
    { "Part of file in this message", "uru.live.file.thislen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_file_data,
    { "Data (gzipped)", "uru.live.file.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_globalreqid,
    { "Global request identifier", "uru.live.vault.globalreqid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_player,
    { "Player KI number", "uru.live.vault.player",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_nodeid,
    { "Node ID", "uru.live.vault.nodeid",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_parent,
    { "Parent Node", "uru.live.vault.parent",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_child,
    { "Child Node", "uru.live.vault.child",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_owner,
    { "Node Owner", "uru.live.vault.owner",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "If != 0, this is usually the PLR node (type 0x02)", HFILL }
  },
  { &hf_urulive_vault_unk0,
    { "Unknown (zeros)", "uru.live.vault.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_itemct,
    { "Items", "uru.live.vault.items",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_ref,
    { "Reference", "uru.live.vault.ref",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_len,
    { "Length", "uru.live.vault.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_createtime,
    { "Create time", "uru.live.vault.createtime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_modifytime,
    { "Modify time", "uru.live.vault.modifytime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_createagename,
    { "Create Age Name", "uru.live.vault.createagename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_createageuuid,
    { "Create Age UUID", "uru.live.vault.createageuuid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_creatoracctid,
    { "Creator Account ID", "uru.live.vault.creatoracctid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_creatorid,
    { "Creator ID", "uru.live.vault.creatorid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_nodetype,
    { "Node type", "uru.live.vault.nodetype",
      FT_UINT8, BASE_DEC, VALS(vnodetypes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_foldertype,
    { "Folder type", "uru.live.vault.foldertype",
      FT_UINT32, BASE_DEC, VALS(vfoldertypes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_agename,
    { "Age display name", "uru.live.vault.agename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_online,
    { "Online", "uru.live.vault.online",
      FT_BOOLEAN, 32, NULL, 0x0,
      "Is player online?", HFILL }
  },
  { &hf_urulive_vault_acct,
    { "Account ID", "uru.live.vault.acct",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_ageUUID,
    { "Age UUID", "uru.live.vault.ageUUID",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_parentUUID,
    { "Parent age UUID", "uru.live.vault.parentUUID",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_age_fname,
    { "Age filename", "uru.live.vault.agefname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_name,
    { "Name", "uru.live.vault.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_type,
    { "Type", "uru.live.vault.type",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_value,
    { "Value", "uru.live.vault.value",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_imgexists,
    { "Image exists", "uru.live.vault.imgexists",
      FT_BOOLEAN, 32, NULL, 0x0,
      "Is there an image in this image node?", HFILL }
  },
  { &hf_urulive_vault_imagename,
    { "Image caption", "uru.live.vault.imagename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_imagelen,
    { "Image length", "uru.live.vault.imagelen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_image,
    { "Image data", "uru.live.vault.image",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_linkpoint,
    { "Link points", "uru.live.vault.linkpoint",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_volatile,
    { "Volatile", "uru.live.vault.volatile",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },

   /* GENERIC types for node data */
  { &hf_urulive_vault_int32_1,
    { "Int32_1", "uru.live.vault.int32_1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_int32_2,
    { "Int32_2", "uru.live.vault.int32_2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_int32_3,
    { "Int32_3", "uru.live.vault.int32_3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_int32_4,
    { "Int32_4", "uru.live.vault.int32_4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uint32_1,
    { "UInt32_1", "uru.live.vault.uint32_1",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uint32_2,
    { "UInt32_2", "uru.live.vault.uint32_2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uint32_3,
    { "UInt32_3", "uru.live.vault.uint32_3",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uint32_4,
    { "UInt32_4", "uru.live.vault.uint32_4",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uuid_1,
    { "Uuid_1", "uru.live.vault.uuid_1",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uuid_2,
    { "Uuid_2", "uru.live.vault.uuid_2",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uuid_3,
    { "Uuid_3", "uru.live.vault.uuid_3",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_uuid_4,
    { "Uuid_4", "uru.live.vault.uuid_4",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_1,
    { "String64_1", "uru.live.vault.string64_1",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_2,
    { "String64_2", "uru.live.vault.string64_2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_3,
    { "String64_3", "uru.live.vault.string64_3",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_4,
    { "String64_4", "uru.live.vault.string64_4",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_5,
    { "String64_5", "uru.live.vault.string64_5",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_string64_6,
    { "String64_6", "uru.live.vault.string64_6",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_istring64_1,
    { "IString64_1", "uru.live.vault.istring64_1",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_istring64_2,
    { "IString64_2", "uru.live.vault.istring64_2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_text_1,
    { "Text_1", "uru.live.vault.text_1",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_text_2,
    { "Text_2", "uru.live.vault.text_2",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_blob_1,
    { "Blob_1", "uru.live.vault.blob_1",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_vault_blob_2,
    { "Blob_2", "uru.live.vault.blob_2",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_create_name,
    { "Avatar name", "uru.live.create.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_create_gender,
    { "Avatar gender", "uru.live.create.gender",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_create_code,
    { "Invitation code", "uru.live.create.code",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_log_python,
    { "Python traceback", "uru.live.log.python",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_holder,
    { "Score holder", "uru.live.score.holder",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "This is a PlayerInfoNode or an AgeInfoNode (hood score)", HFILL }
  },
  { &hf_urulive_score_name,
    { "Name", "uru.live.score.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_unk1,
    { "Unknown", "uru.live.score.unk1",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_mlen,
    { "Message Length", "uru.live.score.mlen",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_id,
    { "Score identifier", "uru.live.score.id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_ts,
    { "Creation timestamp", "uru.live.score.ts",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_type,
    { "Type", "uru.live.score.type",
      FT_UINT32, BASE_DEC, VALS(score_types), 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_value,
    { "Score", "uru.live.score.value",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_add,
    { "Amount to add", "uru.live.score.add",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_score_dest,
    { "Destination identifier", "uru.live.score.dest",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_msgtype,
    { "Game Message Type", "uru.live.gamemgr.msgtype",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_reqid,
    { "Setup request ID", "uru.live.gamemgr.reqid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_len,
    { "Game message length", "uru.live.gamemgr.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_unk0,
    { "Unknown (zeros)", "uru.live.gamemgr.unk0",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_clientid,
    { "Client ID", "uru.live.gamemgr.clientid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_uuid,
    { "Game UUID", "uru.live.gamemgr.uuid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_idresult,
    { "Game ID result", "uru.live.gamemgr.idresult",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_gameid,
    { "Game ID", "uru.live.gamemgr.gameid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_gameclimsg,
    { "Message type", "uru.live.gamemgr.gameclimsg",
      FT_UINT8, BASE_HEX, VALS(gamecli_msgtypes), 0x0,
      "Game client messages", HFILL }
  },
  { &hf_urulive_gamemgr_spiralmsg,
    { "Message type", "uru.live.gamemgr.spiralmsg",
      FT_UINT8, BASE_HEX, VALS(bluespiral_msgtypes), 0x0,
      "Blue Spiral game messages", HFILL }
  },
  { &hf_urulive_gamemgr_clispiralmsg,
    { "Message type", "uru.live.gamemgr.clispiralmsg",
      FT_UINT8, BASE_HEX, VALS(bluespiral_climsgtypes), 0x0,
      "Blue Spiral game messages", HFILL }
  },
  { &hf_urulive_gamemgr_heekmsg,
    { "Message type", "uru.live.gamemgr.heekmsg",
      FT_UINT8, BASE_HEX, VALS(heek_msgtypes), 0x0,
      "Heek game messages", HFILL }
  },
  { &hf_urulive_gamemgr_cliheekmsg,
    { "Message type", "uru.live.gamemgr.cliheekmsg",
      FT_UINT8, BASE_HEX, VALS(heek_climsgtypes), 0x0,
      "Heek game messages", HFILL }
  },
  { &hf_urulive_gamemgr_markermsg,
    { "Message type", "uru.live.gamemgr.markermsg",
      FT_UINT32, BASE_HEX, VALS(marker_msgtypes), 0x0,
      "Marker game messages", HFILL }
  },
  { &hf_urulive_gamemgr_climarkermsg,
    { "Message type", "uru.live.gamemgr.climarkermsg",
      FT_UINT32, BASE_HEX, VALS(marker_climsgtypes), 0x0,
      "Marker game messages", HFILL }
  },
  { &hf_urulive_gamemgr_climbingwallmsg,
    { "Message type", "uru.live.gamemgr.climbingwallmsg",
      FT_UINT8, BASE_HEX, VALS(climbingwall_msgtypes), 0x0,
      "Cllimbing Wall game messages", HFILL }
  },
  { &hf_urulive_gamemgr_varsyncmsg,
    { "Message type", "uru.live.gamemgr.varsyncmsg",
      FT_UINT8, BASE_HEX, VALS(varsync_msgtypes), 0x0,
      "Var Sync game messages", HFILL }
  },
  { &hf_urulive_gamemgr_clivarsyncmsg,
    { "Message type", "uru.live.gamemgr.clivarsyncmsg",
      FT_UINT8, BASE_HEX, VALS(varsync_climsgtypes), 0x0,
      "Var Sync game messages", HFILL }
  },
  { &hf_urulive_gamemgr_template,
    { "Template uuid", "uru.live.gamemgr.template",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_gametype,
    { "Game type", "uru.live.gamemgr.gametype",
      FT_INT8, BASE_DEC, VALS(marker_gametypes), 0x0,
      "Marker game type", HFILL }
  },
  { &hf_urulive_gamemgr_team,
    { "Team", "uru.live.gamemgr.team",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_name,
    { "Name", "uru.live.gamemgr.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_markerposx,
    { "X location", "uru.live.gamemgr.markerpos",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_markerposy,
    { "Y location", "uru.live.gamemgr.markerpos",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_markerposz,
    { "Z location", "uru.live.gamemgr.markerpos",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_markernum,
    { "Marker number", "uru.live.gamemgr.markernum",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_markerdel,
    { "Delete result", "uru.live.gamemgr.markerdel",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_captured,
    { "Captured", "uru.live.gamemgr.captured",
      FT_UINT8, BASE_DEC, VALS(marker_captured), 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_gametime,
    { "Elapsed time (ms)", "uru.live.gamemgr.gametime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Elapsed game time in milliseconds", HFILL }
  },
  { &hf_urulive_gamemgr_timelimit,
    { "Time limit (ms)", "uru.live.gamemgr.timelimit",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Time limit in milliseconds", HFILL }
  },
  { &hf_urulive_gamemgr_extra,
    { "Extra byte", "uru.live.gamemgr.extra",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }
  },
    { &hf_urulive_gamemgr_buf,
    { " *Garbage in a buffer*", "uru.live.gamemgr.buf",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_clothorder,
    { "Cloth order", "uru.live.gamemgr.clothorder",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_rotate,
    { "Door rotate", "uru.live.gamemgr.rotate",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Start door rotation?", HFILL }
  },
  { &hf_urulive_gamemgr_cloth,
    { "Cloth number", "uru.live.gamemgr.cloth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_position,
    { "Position", "uru.live.gamemgr.position",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_ifacestate,
    { "Interface enabled", "uru.live.gamemgr.ifacestate",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Interface enabled?", HFILL }
  },
  { &hf_urulive_gamemgr_countdown,
    { "State", "uru.live.gamemgr.countdown",
      FT_UINT8, BASE_HEX, VALS(heek_countdown_states), 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_rank,
    { "Rank", "uru.live.gamemgr.rank",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_choice,
    { "Choice", "uru.live.gamemgr.choice",
      FT_UINT8, BASE_HEX, VALS(heek_game_choice), 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_score,
    { "Score", "uru.live.gamemgr.score",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_update,
    { "KI message", "uru.live.gamemgr.update",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Send point update message to KI RTChat?", HFILL }
  },
  { &hf_urulive_gamemgr_win,
    { "Win", "uru.live.gamemgr.win",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Play win animation?", HFILL }
  },
  { &hf_urulive_gamemgr_seq,
    { "Animation", "uru.live.gamemgr.seq",
      FT_UINT8, BASE_HEX, VALS(heek_game_seq), 0x0,
      "Done playing this animation.", HFILL }
  },
  { &hf_urulive_gamemgr_light,
    { "Light", "uru.live.gamemgr.light",
      FT_UINT8, BASE_HEX, VALS(heek_light_values), 0x0,
      "Which light to use", HFILL }
  },
  { &hf_urulive_gamemgr_state,
    { "Light", "uru.live.gamemgr.state",
      FT_UINT8, BASE_HEX, VALS(heek_light_states), 0x0,
      "What to do with the light", HFILL }
  },
  { &hf_urulive_gamemgr_id,
    { "ID", "uru.live.gamemgr.id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_value,
    { "Value", "uru.live.gamemgr.value",
      FT_DOUBLE, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemgr_playing,
    { "Playing", "uru.live.gamemgr.playing",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Are we playing?", HFILL }
  },
  { &hf_urulive_gamemgr_single,
    { "Single", "uru.live.gamemgr.single",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Are we the only player?", HFILL }
  },
  { &hf_urulive_gamemgr_enable,
    { "Enable", "uru.live.gamemgr.enable",
      FT_BOOLEAN, 8, NULL, 0x0,
      "Enable buttons?", HFILL }
  },
  { &hf_urulive_friend_uuid,
    { "Invitation UUID", "uru.live.friend.uuid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_friend_addr,
    { "Email address", "uru.live.friend.addr",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_friend_type,
    { "Invite Type (?)", "uru.live.friend.type",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },

  { &hf_urulive_obj_type,
    { "Object Type", "uru.obj.type",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_subobj_type,
    { "  Object Type", "uru.obj.type",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_obj_new,
    { "PRP file index", "uru.obj.prpidx",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_subobj_new,
    { "  PRP file index", "uru.subobj.prpidx",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_gamemsg_type,
    { "Type", "uru.gamemsg.type",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_loadclone_subtype,
    { "  Submessage type", "uru.loadclone.subtype",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_loadclone_subctype,
    { "  Submsg unknown (creator type?)", "uru.loadclone.subctype",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_loadclone_name,
    { "  Name", "uru.loadclone.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_avtask_type,
    { "Type", "uru.avtask.type",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_avtask_braintype,
    { "Brain type", "uru.avtask.braintype",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_avtask_stagetype,
    { "Stage type", "uru.avtask.stagetype",
      FT_UINT16, BASE_HEX, VALS(live_typecodes), 0x0,
      "", HFILL }
  },
  { &hf_urulive_groupid_bytes,
    { "Unknown", "uru.live.groupid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "", HFILL }
  },
  { &hf_urulive_kimsg_extra,
    { "Mystery zeros", "uru.live.kimsg.extra",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }
  }
};
