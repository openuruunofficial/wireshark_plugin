/*
 *
 * UruLive typecodes
 *
 */

/* $Id: $ */

#ifndef _URULIVE_MSG_TYPECODES_H_
#define _URULIVE_MSG_TYPECODES_H_

#define kCli2Auth_PingRequest 0x00
#define kCli2Auth_ClientRegisterRequest 0x01
#define kCli2Auth_ClientSetCCRLevel 0x02
#define kCli2Auth_AcctLoginRequest 0x03
#define kCli2Auth_AcctSetPlayerRequest 0x06
#define kCli2Auth_AcctCreateRequest 0x07
#define kCli2Auth_AcctChangePasswordRequest 0x08
#define kCli2Auth_AcctSetRolesRequest 0x09
#define kCli2Auth_AcctSetBillingTypeRequest 0x0A
#define kCli2Auth_AcctActivateRequest 0x0B
#define kCli2Auth_AcctCreateFromKeyRequest 0x0C
#define kCli2Auth_PlayerDeleteRequest 0x0D
#define kCli2Auth_PlayerCreateRequest 0x11
#define kCli2Auth_UpgradeVisitorRequest 0x14
#define kCli2Auth_SetPlayerBanStatusRequest 0x15
#define kCli2Auth_KickPlayer 0x16
#define kCli2Auth_ChangePlayerNameRequest 0x17
#define kCli2Auth_SendFriendInviteRequest 0x18
#define kCli2Auth_VaultNodeCreate 0x19
#define kCli2Auth_VaultNodeFetch 0x1A
#define kCli2Auth_VaultNodeSave 0x1B
#define kCli2Auth_VaultNodeAdd 0x1D
#define kCli2Auth_VaultNodeRemove 0x1E
#define kCli2Auth_VaultFetchNodeRefs 0x1F
#define kCli2Auth_VaultInitAgeRequest 0x20
#define kCli2Auth_VaultNodeFind 0x21
#define kCli2Auth_VaultSetSeen 0x22
#define kCli2Auth_VaultSendNode 0x23
#define kCli2Auth_AgeRequest 0x24
#define kCli2Auth_FileListRequest 0x25
#define kCli2Auth_FileDownloadRequest 0x26
#define kCli2Auth_FileDownloadChunkAck 0x27
#define kCli2Auth_PropagateBuffer 0x28
#define kCli2Auth_GetPublicAgeList 0x29
#define kCli2Auth_SetAgePublic 0x2A
#define kCli2Auth_LogPythonTraceback 0x2B
#define kCli2Auth_LogStackDump 0x2C
#define kCli2Auth_LogClientDebuggerConnect 0x2D
#define kCli2Auth_ScoreCreate 0x2E
#define kCli2Auth_ScoreDelete 0x2F
#define kCli2Auth_ScoreGetScores 0x30
#define kCli2Auth_ScoreAddPoints 0x31
#define kCli2Auth_ScoreTransferPoints 0x32
#define kCli2Auth_ScoreSetPoints 0x33
#define kCli2Auth_ScoreGetRanks 0x34

#define kAuth2Cli_PingReply 0x00
#define kAuth2Cli_ServerAddr 0x01
#define kAuth2Cli_NotifyNewBuild 0x02
#define kAuth2Cli_ClientRegisterReply 0x03
#define kAuth2Cli_AcctLoginReply 0x04
#define kAuth2Cli_AcctPlayerInfo 0x06
#define kAuth2Cli_AcctSetPlayerReply 0x07
#define kAuth2Cli_AcctCreateReply 0x08
#define kAuth2Cli_AcctChangePasswordReply 0x09
#define kAuth2Cli_AcctSetRolesReply 0x0A
#define kAuth2Cli_AcctSetBillingTypeReply 0x0B
#define kAuth2Cli_AcctActivateReply 0x0C
#define kAuth2Cli_AcctCreateFromKeyReply 0x0D
#define kAuth2Cli_PlayerCreateReply 0x10
#define kAuth2Cli_PlayerDeleteReply 0x11
#define kAuth2Cli_UpgradeVisitorReply 0x12
#define kAuth2Cli_SetPlayerBanStatusReply 0x13
#define kAuth2Cli_ChangePlayerNameReply 0x14
#define kAuth2Cli_SendFriendInviteReply 0x15
#define kAuth2Cli_VaultNodeCreated 0x17
#define kAuth2Cli_VaultNodeFetched 0x18
#define kAuth2Cli_VaultNodeChanged 0x19
#define kAuth2Cli_VaultNodeDeleted 0x1A
#define kAuth2Cli_VaultNodeAdded 0x1B
#define kAuth2Cli_VaultNodeRemoved 0x1C
#define kAuth2Cli_VaultNodeRefsFetched 0x1D
#define kAuth2Cli_VaultInitAgeReply 0x1E
#define kAuth2Cli_VaultNodeFindReply 0x1F
#define kAuth2Cli_VaultSaveNodeReply 0x20
#define kAuth2Cli_VaultAddNodeReply 0x21
#define kAuth2Cli_VaultRemoveNodeReply 0x22
#define kAuth2Cli_AgeReply 0x23
#define kAuth2Cli_FileListReply 0x24
#define kAuth2Cli_FileDownloadChunk 0x25
#define kAuth2Cli_PropagateBuffer 0x26
#define kAuth2Cli_KickedOff 0x27
#define kAuth2Cli_PublicAgeList 0x28
#define kAuth2Cli_ScoreCreateReply 0x29
#define kAuth2Cli_ScoreDeleteReply 0x2A
#define kAuth2Cli_ScoreGetScoresReply 0x2B
#define kAuth2Cli_ScoreAddPointsReply 0x2C
#define kAuth2Cli_ScoreTransferPointsReply 0x2D
#define kAuth2Cli_ScoreSetPointsReply 0x2E
#define kAuth2Cli_ScoreGetRanksReply 0x2F

#define kCli2Game_PingRequest 0x00
#define kCli2Game_JoinAgeRequest 0x01
#define kCli2Game_PropagateBuffer 0x02
#define kCli2Game_GameMgrMsg 0x03

#define kGame2Cli_PingReply 0x00
#define kGame2Cli_JoinAgeReply 0x01
#define kGame2Cli_PropagateBuffer 0x02
#define kGame2Cli_GameMgrMsg 0x03

#define kCli2GateKeeper_PingRequest 0x00
#define kCli2GateKeeper_FileSrvIpAddressRequest 0x01
#define kCli2GateKeeper_AuthSrvIpAddressRequest 0x02

#define kGateKeeper2Cli_PingReply 0x00
#define kGateKeeper2Cli_FileSrvIpAddressReply 0x01
#define kGateKeeper2Cli_AuthSrvIpAddressReply 0x02

#define kCli2Csr_PingRequest 0x00
#define kCli2Csr_RegisterRequest 0x01
#define kCli2Csr_LoginRequest 0x02
#define kCsr2Cli_PingReply 0x00
#define kCsr2Cli_RegisterReply 0x01
#define kCsr2Cli_LoginReply 0x02

/* these are the older values */

#define kCli2Auth_PingRequest_v1 0x00
#define kCli2Auth_ClientRegisterRequest_v1 0x0A
#define kCli2Auth_ClientSetCCRLevel_v1 0x0B
#define kCli2Auth_AcctLoginRequest_v1 0x14
#define kCli2Auth_AcctSetPlayerRequest_v1 0x17
#define kCli2Auth_AcctCreateRequest_v1 0x18
#define kCli2Auth_AcctChangePasswordRequest_v1 0x19
#define kCli2Auth_AcctSetRolesRequest_v1 0x1A
#define kCli2Auth_AcctSetBillingTypeRequest_v1 0x1B
#define kCli2Auth_AcctActivateRequest_v1 0x1C
#define kCli2Auth_AcctCreateFromKeyRequest_v1 0x1D
#define kCli2Auth_PlayerDeleteRequest_v1 0x28
#define kCli2Auth_PlayerCreateRequest_v1 0x2C
#define kCli2Auth_UpgradeVisitorRequest_v1 0x2F
#define kCli2Auth_SetPlayerBanStatusRequest_v1 0x30 /* new */
#define kCli2Auth_KickPlayer_v1 0x31 /* new */
#define kCli2Auth_ChangePlayerNameRequest_v1 0x32 /* new */
#define kCli2Auth_VaultNodeCreate_v1 0x50
#define kCli2Auth_VaultNodeFetch_v1 0x51
#define kCli2Auth_VaultNodeSave_v1 0x52
#define kCli2Auth_VaultNodeAdd_v1 0x54
#define kCli2Auth_VaultNodeRemove_v1 0x55
#define kCli2Auth_VaultFetchNodeRefs_v1 0x56
#define kCli2Auth_VaultInitAgeRequest_v1 0x57
#define kCli2Auth_VaultNodeFind_v1 0x58
#define kCli2Auth_VaultSetSeen_v1 0x59
#define kCli2Auth_VaultSendNode_v1 0x5A
#define kCli2Auth_VaultScoreAddPoints_v1 0x5B /* new */
#define kCli2Auth_VaultScoreTransferPoints_v1 0x5C /* new */
#define kCli2Auth_AgeRequest_v1 0x64
#define kCli2Auth_FileListRequest_v1 0x78
#define kCli2Auth_FileDownloadRequest_v1 0x79
#define kCli2Auth_FileDownloadChunkAck_v1 0x7A /* new */
#define kCli2Auth_PropagateBuffer_v1 0x8C
#define kCli2Auth_GetPublicAgeList_v1 0xB4
#define kCli2Auth_SetAgePublic_v1 0xB5
#define kCli2Auth_LogPythonTraceback_v1 0xC8
#define kCli2Auth_LogStackDump_v1 0xC9
#define kCli2Auth_LogClientDebuggerConnect_v1 0xCA /* new */


#define kAuth2Cli_PingReply_v1 0x00
#define kAuth2Cli_ServerAddr_v1 0x03
#define kAuth2Cli_NotifyNewBuild_v1 0x04
#define kAuth2Cli_ClientRegisterReply_v1 0x0A
#define kAuth2Cli_AcctLoginReply_v1 0x14
#define kAuth2Cli_AcctPlayerInfo_v1 0x16
#define kAuth2Cli_AcctSetPlayerReply_v1 0x17
#define kAuth2Cli_AcctCreateReply_v1 0x18
#define kAuth2Cli_AcctChangePasswordReply_v1 0x19
#define kAuth2Cli_AcctSetRolesReply_v1 0x1A
#define kAuth2Cli_AcctSetBillingTypeReply_v1 0x1B
#define kAuth2Cli_AcctActivateReply_v1 0x1C
#define kAuth2Cli_AcctCreateFromKeyReply_v1 0x1D
#define kAuth2Cli_PlayerCreateReply_v1 0x2A
#define kAuth2Cli_PlayerDeleteReply_v1 0x2B
#define kAuth2Cli_UpgradeVisitorReply_v1 0x2C
#define kAuth2Cli_SetPlayerBanStatusReply_v1 0x2D /* new */
#define kAuth2Cli_ChangePlayerNameReply_v1 0x2E /* new */
#define kAuth2Cli_VaultNodeCreated_v1 0x50
#define kAuth2Cli_VaultNodeFetched_v1 0x51
#define kAuth2Cli_VaultNodeChanged_v1 0x52
#define kAuth2Cli_VaultNodeDeleted_v1 0x53
#define kAuth2Cli_VaultNodeAdded_v1 0x54
#define kAuth2Cli_VaultNodeRemoved_v1 0x55
#define kAuth2Cli_VaultNodeRefsFetched_v1 0x56
#define kAuth2Cli_VaultInitAgeReply_v1 0x57
#define kAuth2Cli_VaultNodeFindReply_v1 0x58
#define kAuth2Cli_VaultSaveNodeReply_v1 0x59 /* new */
#define kAuth2Cli_VaultAddNodeReply_v1 0x5A /* new */
#define kAuth2Cli_VaultRemoveNodeReply_v1 0x5B /* new */
#define kAuth2Cli_AgeReply_v1 0x64
#define kAuth2Cli_FileListReply_v1 0x78
/* #define kAuth2Cli_FileDownloadReply_v1 0x79 - renamed */
#define kAuth2Cli_FileDownloadChunk_v1 0x79
#define kAuth2Cli_PropagateBuffer_v1 0x8C
#define kAuth2Cli_KickedOff_v1 0xA0
#define kAuth2Cli_PublicAgeList_v1 0xB4
#define kAuth2Cli_VaultScoreAddPointsReply_v1 0xC8 /* new */
#define kAuth2Cli_VaultScoreTransferPointsReply_v1 0xC9 /* new */

#define kCli2Game_PingRequest_v1 0x00
#define kCli2Game_JoinAgeRequest_v1 0x14
#define kCli2Game_PropagateBuffer_v1 0x1E
#define kCli2Game_GameMgrMsg_v1 0x1F

#define kGame2Cli_PingReply_v1 0x00
#define kGame2Cli_JoinAgeReply_v1 0x14
#define kGame2Cli_PropagateBuffer_v1 0x1E
#define kGame2Cli_GameMgrMsg_v1 0x1F



#endif
