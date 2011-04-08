/* 
   Please note, this file is meant to #included, one time only, in the
   main packet-uru.c file.  It should not be compiled standalone.
   This file exists to preserve my sanity while writing the dissectors,
   because I spend a lot of time changing the contents of the header
   fields around (since I am not working with a documented protocol and
   cannot just list them up front).
*/

/*
 * urumoss-hf.c
 * The hf_register_info array for the MOSS backend protocol.
 *
 * Copyright (C) 2008-2011  a'moaca'
 *
 * $Id $
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

static int hf_moss_msglen = -1;
static int hf_moss_msgtype = -1;
static int hf_moss_id1 = -1;
static int hf_moss_id2 = -1;

static int hf_moss_servertypes = -1;
static int hf_moss_protocol_version = -1;
static int hf_moss_killreason = -1;
static int hf_moss_login_authtype = -1;
static int hf_moss_accttype = -1;
static int hf_moss_download_name = -1;
static int hf_moss_restrict_type = -1;
static int hf_moss_fail_reason = -1;
static int hf_moss_final_shutdown = -1;
static int hf_moss_player_present = -1;
static int hf_moss_sdlupdate_type = -1;
static int hf_moss_recip_off = -1;
static int hf_moss_marker_dbid = -1;
static int hf_moss_marker_gameexists = -1;
static int hf_moss_marker_count = -1;
static int hf_moss_marker_captured = -1;
static int hf_moss_gate_reqid2 = -1;
static int hf_moss_gate_auth = -1;
static int hf_moss_gate_file = -1;
static int hf_moss_gate_game = -1;
static int hf_moss_gate_type = -1;
static int hf_moss_gate_addrtype = -1;
static int hf_moss_gate_ipaddr = -1;
static int hf_moss_gate_name = -1;
static int hf_moss_gate_push = -1;

static const value_string moss_typecodes[] = {
  { AUTH_ACCT_LOGIN, "[Frontend] Auth Account Login Request" },
  { AUTH_ACCT_LOGIN|FROM_SERVER, "[Backend] Auth Account Login Reply" },
  { AUTH_KI_VALIDATE, "[Frontend] Auth KI# Validate Request" },
  { AUTH_KI_VALIDATE|FROM_SERVER, "[Backend] Auth KI# Validate Reply" },
  { AUTH_PLAYER_LOGOUT, "[Frontend] Auth Player Logged Out" },
  { VAULT_PLAYER_CREATE, "[Frontend] Vault Player Create Request" },
  { VAULT_PLAYER_CREATE|FROM_SERVER, "[Backend] Vault Player Create Reply" },
  { VAULT_PLAYER_DELETE, "[Frontend] Vault Player Delete Request" },
  { VAULT_PLAYER_DELETE|FROM_SERVER, "[Backend] Vault Player Delete Reply" },
  { VAULT_PASSTHRU, "[Frontend] Vault Passthrough" },
  { VAULT_PASSTHRU|FROM_SERVER, "[Backend] Vault Passthrough" },
  { VAULT_FETCHREFS, "[Frontend] Vault Fetch Refs Request" },
  { VAULT_FETCHREFS|FROM_SERVER, "[Backend] Vault Fetch Refs Reply" },
  { VAULT_FINDNODE, "[Frontend] Vault Find Node Request" },
  { VAULT_FINDNODE|FROM_SERVER, "[Backend] Vault Find Node Reply" },
  { VAULT_FETCH, "[Frontend] Vault Fetch Request" },
  { VAULT_FETCH|FROM_SERVER, "[Backend] Vault Fetch Reply" },
  { VAULT_SAVENODE, "[Frontend] Vault Node Save Request" },
  { VAULT_SAVENODE|FROM_SERVER, "[Backend] Vault Node Save Reply" },
  { VAULT_CREATENODE, "[Frontend] Vault Node Create Request" },
  { VAULT_CREATENODE|FROM_SERVER, "[Backend] Vault Node Create Reply" },
  { VAULT_ADDREF, "[Frontend] Vault Ref Add Request" },
  { VAULT_ADDREF|FROM_SERVER, "[Backend] Vault Ref Add Reply" },
  { VAULT_REMOVEREF, "[Frontend] Vault Ref Remove Request" },
  { VAULT_REMOVEREF|FROM_SERVER, "[Backend] Vault Ref Remove Reply" },
  { VAULT_INIT_AGE, "[Frontend] Vault Init Age Request" },
  { VAULT_INIT_AGE|FROM_SERVER, "[Backend] Vault Init Age Reply" },
  { VAULT_AGE_LIST, "[Frontend] Vault Public Age List Request" },
  { VAULT_AGE_LIST|FROM_SERVER, "[Backend] Vault Public Age List Reply" },
  { VAULT_SENDNODE, "[Frontend] Vault Send Node Request" },
  { VAULT_SET_AGE_PUBLIC, "[Frontend] Vault Set Age Public/Private Request" },
  { VAULT_NODE_CHANGED|FROM_SERVER, "[Backend] Vault Node Changed Notify" },
  { VAULT_REF_ADDED|FROM_SERVER, "[Backend] Vault Ref Added Notify" },
  { VAULT_REF_REMOVED|FROM_SERVER, "[Backend] Vault Ref Removed Notify" },
  { VAULT_SCORE_CREATE, "[Frontend] Vault Score Create Request" },
  { VAULT_SCORE_CREATE|FROM_SERVER, "[Frontend] Vault Score Create Reply" },
  { VAULT_SCORE_GET, "[Frontend] Vault Score Get Request" },
  { VAULT_SCORE_GET|FROM_SERVER, "[Frontend] Vault Score Get Reply" },
  { VAULT_SCORE_ADD, "[Frontend] Vault Add to Score Request" },
  { VAULT_SCORE_ADD|FROM_SERVER, "[Frontend] Vault Add to Score Reply" },
  { VAULT_SCORE_XFER, "[Frontend] Vault Transfer Score Request" },
  { VAULT_SCORE_XFER|FROM_SERVER, "[Frontend] Vault Transfer Score Reply" },
  { ADMIN_HELLO, "[Frontend] Hello to Backend" },
  { ADMIN_HELLO|FROM_SERVER, "[Backend] Hello to Frontend" },
  { ADMIN_KILL_CLIENT|FROM_SERVER, "[Backend] Kill Client Connection Command" },
  { TRACK_PING, "[Frontend] Ping to Tracking" },
  { TRACK_SERVICE_TYPES, "[Frontend] Dispatcher Service Types" },
  { TRACK_FIND_SERVICE, "[Frontend] Gatekeeper Find Service Request" },
  { TRACK_FIND_SERVICE|FROM_SERVER, "[Backend] Gatekeeper Find Service Reply" },
  { TRACK_DISPATCHER_HELLO, "[Frontend] Dispatcher Available" },
  { TRACK_DISPATCHER_BYE, "[Frontend] Dispatcher Unavailable" },
  { TRACK_GAME_HELLO, "[Frontend] Game Server Available" },
  { TRACK_GAME_BYE, "[Frontend] Game Server Shutdown Notify" },
  { TRACK_GAME_BYE|FROM_SERVER, "[Backend] Game Server Shutdown Reply" },
  { TRACK_GAME_PLAYERINFO, "[Frontend] Player Age Presence Info" },
  { TRACK_INTERAGE_FWD, "[Frontend] Interage Message Forward" },
  { TRACK_INTERAGE_FWD|FROM_SERVER, "[Backend] Interage Message Forward" },
  { TRACK_SDL_UPDATE|FROM_SERVER, "[Backend] Vault SDL Update Notify" },
  { TRACK_NEXT_GAMEID, "[Frontend] GameMgr ID Request" },
  { TRACK_NEXT_GAMEID|FROM_SERVER, "[Frontend] GameMgr ID Reply" },
  { TRACK_FIND_GAME, "[Frontend] Game Server Request" },
  { TRACK_FIND_GAME|FROM_SERVER, "[Backend] Game Server Reply" },
  { TRACK_START_GAME|FROM_SERVER, "[Backend] Game Server Startup Request" },
  { TRACK_START_GAME, "[Frontend] Game Server Startup Nack" },
  { TRACK_ADD_PLAYER|FROM_SERVER, "[Backend] Game Register Player Request" },
  { TRACK_ADD_PLAYER, "[Frontend] Game Register Player Reply" },
  { MARKER_NEWGAME, "[Frontend] Set Up Marker Game Request" },
  { MARKER_NEWGAME|FROM_SERVER, "[Backend] Set Up Marker Game Reply" },
  { MARKER_ADD, "[Frontend] Add New Marker Request" },
  { MARKER_ADD|FROM_SERVER, "[Backend] Add New Marker Reply" },
  { MARKER_GAME_RENAME, "[Frontend] Rename Marker Game Request" },
  { MARKER_GAME_RENAME|FROM_SERVER, "[Backend] Rename Marker Game Reply" },
  { MARKER_GAME_DELETE, "[Frontend] Delete Marker Game Request" },
  { MARKER_GAME_DELETE|FROM_SERVER, "[Backend] Delete Marker Game Reply" },
  { MARKER_RENAME, "[Frontend] Rename Marker Request" },
  { MARKER_RENAME|FROM_SERVER, "[Backend] Rename Marker Reply" },
  { MARKER_DELETE, "[Frontend] Delete Marker Request" },
  { MARKER_DELETE|FROM_SERVER, "[Backend] Delete Marker Reply" },
  { MARKER_CAPTURE, "[Frontend] Capture Marker Request" },
  { MARKER_CAPTURE|FROM_SERVER, "[Backend] Capture Marker Reply" },
  { MARKER_GAME_STOP, "[Frontend] Stop Marker Game Request" },
  { MARKER_DUMP|FROM_SERVER, "[Backend] Marker List" },
  { MARKER_STATE|FROM_SERVER, "[Backend] Captured Markers List" },
  { 0, NULL }
};

static const value_string moss_accttypes[] = {
  { 0x0, "Free" },
  { 0x1, "Paid" },
  { 0, NULL }
};

static const value_string moss_killreasons[] = {
  { 1, "DB \"in doubt\" error" },
  { 2, "Server does not have state required to fulfill request" },
  { 3, "A new login for this account occurred" },
  { 4, "Auth disconnected for this player" },
  { 0, NULL }
};

static const value_string moss_authtypes[] = {
  { 0, "Basic password hash" },
  { 1, "Challenge-reponse auth" },
  { 0, NULL }
};

static const value_string moss_failreasons[] = {
  { 0, "None" },
  { 1, "Disabled by configuration" },
  { 2, "Cannot read .age file" },
  { 3, "Cannot read common SDL" },
  { 4, "Failed to acquire resources" },
  { 10, "Server shutting down" },
  { 0, NULL }
};

static const value_string moss_servertypes[] = {
  { NegotiateAuth, "Auth" },
  { NegotiateFile, "File" },
  { NegotiateGame, "Game" },
  { NegotiateGate, "Gatekeeper" },
  { CLASS_AUTH|CLASS_VAULT|CLASS_TRACK, "Backend (all)" },
  { 0, "Dispatcher" },
  { 0, NULL }
};

static const value_string moss_sdlupdates[] = {
  { 0, "Invalid" },
  { 1, "Global SDL for age startup" },
  { 2, "Global SDL updated" },
  { 3, "Vault SDL updated" },
  { 4, "Vault SDL for age load" },
  { 0, NULL }
};

static const value_string moss_gatetypes[] = {
  { 0, "Auth" },
  { 1, "File" },
  { 0, NULL }
};

static const value_string moss_addrtypes[] = {
  { 0, "None" },
  { 1, "Hostname" },
  { 2, "IP address" },
  { 0, NULL }
};

static hf_register_info hf_moss[] = {
  { &hf_moss_msglen,
    { "Message length", "moss.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "The total length of the message", HFILL }
  },
  { &hf_moss_msgtype,
    { "Message type", "moss.type",
      FT_UINT32, BASE_HEX, VALS(moss_typecodes), 0x0,
      "The type of the message", HFILL }
  },
  { &hf_moss_id1,
    { "Frontend server ID part 1", "moss.id1",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "Part 1 of the frontend server ID (an IP address)", HFILL }
  },
  { &hf_moss_id2,
    { "Frontend server ID part 2", "moss.id2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "Part 2 of the frontend server ID (a thread/process ID)", HFILL }
  },

  { &hf_moss_servertypes,
    { "Server type", "moss.server_type",
      FT_UINT32, BASE_HEX, VALS(moss_servertypes), 0x0,
      "What kind of MOSS server this is", HFILL }
  },
  { &hf_moss_protocol_version,
    { "Backend protocol version", "moss.proto_vers",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Maximum backend protocol version", HFILL }
  },
  { &hf_moss_killreason,
    { "Reason", "moss.kill_reason",
      FT_UINT32, BASE_DEC, VALS(moss_killreasons), 0x0,
      "Why the client connection should be closed", HFILL }
  },
  { &hf_moss_login_authtype,
    { "Auth type", "moss.login_auth",
      FT_UINT32, BASE_DEC, VALS(moss_authtypes), 0x0,
      "Authentication algorithm to use during login", HFILL }
  },
  { &hf_moss_accttype,
    { "Account type", "moss.account_type",
      FT_UINT32, BASE_DEC, VALS(moss_accttypes), 0x0,
      "What kind of account this is", HFILL }
  },
  { &hf_moss_download_name,
    { "Directory name", "moss.download_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Name of \"secure download\" directory to use", HFILL }
  },
  { &hf_moss_restrict_type,
    { "Allowed Server Restriction Type", "moss.restrict_type",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Game server restriction type", HFILL }
  },
  { &hf_moss_fail_reason,
    { "Reason", "moss.fail_reason",
      FT_UINT32, BASE_DEC, VALS(moss_failreasons), 0x0,
      "Why no game server was started up", HFILL }
  },
  { &hf_moss_final_shutdown,
    { "Final shutdown", "moss.final_shutdown",
      FT_BOOLEAN, 32, TFS(&yes_no), 0x0,
      "Game server shutdown handshake stage", HFILL }
  },
  { &hf_moss_player_present,
    { "Player is present in age", "moss.player_here",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "Whether the listed player has arrived or left the age", HFILL }
  },
  { &hf_moss_sdlupdate_type,
    { "Type of update", "moss.sdlupdate_type",
      FT_UINT32, BASE_DEC, VALS(moss_sdlupdates), 0x0,
      "The cause for this vault SDL update", HFILL }
  },
  { &hf_moss_recip_off,
    { "Offset of recipients", "moss.recip_off",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "The offset in the forwarded message of the recipient list", HFILL }
  },
  { &hf_moss_marker_dbid,
    { "Internal game ID", "moss.marker_id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Server-internal (DB) unique marker game ID", HFILL }
  },
  { &hf_moss_marker_gameexists,
    { "Marker game exists", "moss.marker_gameexists",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "Whether the game exists already or not", HFILL }
  },
  { &hf_moss_marker_count,
    { "Number of markers", "moss.marker_ct",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "The number of markers in the list", HFILL }
  },
  { &hf_moss_marker_captured,
    { "Captured", "moss.marker_cap",
      FT_UINT32, BASE_DEC, VALS(marker_captured), 0x0,
      "Marker capture type", HFILL }
  },
  { &hf_moss_gate_reqid2,
    {"Additional request identifier", "moss.gate_reqid2",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      "Extra identifier for gatekeeper requests", HFILL }
  },
  { &hf_moss_gate_auth,
    { "Auth service?", "moss.gate_auth",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "Whether or not auth service is provided", HFILL }
  },
  { &hf_moss_gate_file,
    { "File service?", "moss.gate_file",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "Whether or not file service is provided", HFILL }
  },
  { &hf_moss_gate_game,
    { "Game service?", "moss.gate_game",
      FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
      "Whether or not game service is provided", HFILL }
  },
  { &hf_moss_gate_type,
    { "Service type", "moss.gate_type",
      FT_UINT8, BASE_DEC, VALS(moss_gatetypes), 0x0,
      "What type of server is required", HFILL }
  },
  { &hf_moss_gate_addrtype,
    { "Address type", "moss.gate_addrtype",
      FT_UINT8, BASE_DEC, VALS(moss_addrtypes), 0x0,
      "What type of file/auth server address this is", HFILL }
  },
  { &hf_moss_gate_ipaddr,
    { "IP address", "moss.gate_ipaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "IP address of file/auth server", HFILL }
  },
  { &hf_moss_gate_name,
    { "Hostname", "moss.gate_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Hostname of file/auth server", HFILL }
  },
  { &hf_moss_gate_push,
    { "Push updates?", "moss.gate_push",
      FT_BOOLEAN, 32, TFS(&yes_no), 0x0,
      "Whether the backend should push gatekeeper data to frontend", HFILL }
  }
};
