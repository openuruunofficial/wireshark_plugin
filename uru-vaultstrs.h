/*******************************************************************************
*    Alcugs H'uru server                                                       *
*                                                                              *
*    Copyright (C) 2004-2005  The Alcugs H'uru Server Team                     *
*    See the file AUTHORS for more info about the team                         *
*                                                                              *
*    This program is free software; you can redistribute it and/or modify      *
*    it under the terms of the GNU General Public License as published by      *
*    the Free Software Foundation; either version 2 of the License, or         *
*    (at your option) any later version.                                       *
*                                                                              *
*    This program is distributed in the hope that it will be useful,           *
*    but WITHOUT ANY WARRANTY; without even the implied warranty of            *
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
*    GNU General Public License for more details.                              *
*                                                                              *
*    You should have received a copy of the GNU General Public License         *
*    along with this program; if not, write to the Free Software               *
*    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
*                                                                              *
*    Please see the file COPYING for the full license.                         *
*    Please see the file DISCLAIMER for more details, before doing nothing.    *
*                                                                              *
*                                                                              *
*******************************************************************************/

#ifndef _VAULT_STRUCTS
#define _VAULT_STRUCTS
#define _VAULT_STRUCTS_ID "Alcugs-Id: vaultstrs.h 213 2005-04-30 18:45:56Z almlys "

//masks!!
#define MIndex     0x00000001 //00000001 (unkB 1) [Index] *
#define MType      0x00000002 //00000010 (unkB 1) [Type] *
#define MPerms     0x00000004 //00000100 (unkB 1) [Permissions] *
#define MOwner     0x00000008 //00001000 (unkB 1) [Owner ID] *
#define MUnk1      0x00000010 //00010000 (unkB 1) [Group ID] *
#define MStamp1    0x00000020 //00100000 (unkB 1) [Modify Time] *
#define MId1       0x00000040 //01000000 (unkB 1) [Creator ID]
#define MStamp2    0x00000080 //10000000 (unkB 1) [Create Time]
#define MStamp3    0x00000100 //00000001 (unkB 2) [Create Age Time]
#define MAgeCoords 0x00000200 //00000010 (unkB 2) [Create Age Coords]
#define MAgeName   0x00000400 //00000100 (unkB 2) [Create Age Name]
#define MHexGuid   0x00000800 //00001000 (unkB 2) [Create Age Guid]
#define MTorans    0x00001000 //00010000 (unkB 2) [Int32_1]
#define MDistance  0x00002000 //00100000 (unkB 2) [Int32_2]
#define MElevation 0x00004000 //01000000 (unkB 2) [Int32_3]
#define MUnk5      0x00008000 //10000000 (unkB 2) [Int32_4]
#define MId2       0x00010000 //00000001 (unkB 3) [UInt32_1]
#define MUnk7      0x00020000 //00000010 (unkB 3) [UInt32_2]
#define MUnk8      0x00040000 //00000100 (unkB 3) [UInt32_3]
#define MUnk9      0x00080000 //00001000 (unkB 3) [UInt32_4]
#define MEntryName 0x00100000 //00010000 (unkB 3) [String64_1]
#define MSubEntry  0x00200000 //00100000 (unkB 3) [String64_2]
#define MOwnerName 0x00400000 //01000000 (unkB 3) [String64_3]
#define MGuid      0x00800000 //10000000 (unkB 3) [String64_4]
#define MStr1      0x01000000 //00000001 (unkB 4) [String64_5]
#define MStr2      0x02000000 //00000010 (unkB 4) [String64_6]
#define MAvie      0x04000000 //00000100 (unkB 4) [lString64_1]
#define MUid       0x08000000 //00001000 (unkB 4) [lString64_2]
#define MEValue    0x10000000 //00010000 (unkB 4) [Text_1]
#define MEntry2    0x20000000 //00100000 (unkB 4) [Text_2]
#define MData1     0x40000000 //01000000 (unkB 4) [Blob1]
#define MData2     0x80000000 //10000000 (unkB 4) [Blob2]
#define MBlob1     0x00000001 //00000001 (unkC 1) [Blob1_guid]
#define MBlob2     0x00000002 //00000010 (unkC 1) [Blob2_guid]

//define the base vault index
#define KVaultID 20001

//seen node types
#define KInvalidNode 0x00

#define KVNodeMgrPlayerNode 0x02 //2
#define KVNodeMgrAgeNode 0x03
#define KVNodeMgrGameServerNode 0x04
#define KVNodeMgrAdminNode 0x05
#define KVNodeMgrServerNode 0x06
#define KVNodeMgrCCRNode 0x07

#define KFolderNode 0x16 //22
#define KPlayerInfoNode 0x17 //23
#define KSystem 0x18 //24
#define KImageNode 0x19 //25
#define KTextNoteNode 0x1A //26
#define KSDLNode 0x1B //27
#define KAgeLinkNode 0x1C //28
#define KChronicleNode 0x1D //29
#define KPlayerInfoListNode 0x1E //30

#define KMarkerNode 0x20 //32
#define KAgeInfoNode 0x21 //33
#define KAgeInfoListNode 0x22
#define KMarkerListNode 0x23 //35

//permissions
#define KOwnerRead 0x01
#define KOwnerWrite 0x02
#define KGroupRead 0x04
#define KGroupWrite 0x08
#define KOtherRead 0x10
#define KOtherWrite 0x20

//0x01 + 0x02 + 0x04 + 0x10
#define KDefaultPermissions 0x17
/* where persmissions are
-------------------------
| Other | Group | Owner |
-------------------------
| w | r | w | r | w | r |
-------------------------
*/

//folder types
#define KGeneric 0
#define KInboxFolder 1
#define KBuddyListFolder 2
#define KIgnoreListFolder 3
#define KPeopleIKnowAboutFolder 4
#define KVaultMgrGlobalDataFolder 5
#define KChronicleFolder 6
#define KAvatarOutfitFolder 7
#define KAgeTypeJournalFolder 8
#define KSubAgesFolder 9
#define KDeviceInboxFolder 10
#define KHoodMembersFolder 11
#define KAllPlayersFolder 12
#define KAgeMembersFolder 13
#define KAgeJournalsFolder 14
#define KAgeDevicesFolder 15
#define KAgeInstaceSDLNode 16
#define KAgeGlobalSDLNode 17
#define KCanVisitFolder 18
#define KAgeOwnersFolder 19
#define KAllAgeGlobalSDLNodesFolder 20
#define KPlayerInfoNodeFolder 21
#define KPublicAgesFolder 22
#define KAgesIOwnFolder 23
#define KAgesICanVisitFolder 24
#define KAvatarClosetFolder 25
#define KAgeInfoNodeFolder 26
#define KSystemNode 27
#define KPlayerInviteFolder 28
#define KCCRPlayersFolder 29
#define KGlobalInboxFolder 30
#define KChildAgesFolder 31
//end folder types

//vault operations
#define VConnect 0x01
#define VDisconnect 0x02
#define VAddNodeRef 0x03
#define VRemoveNodeRef 0x04
#define VNegotiateManifest 0x05
#define VSaveNode 0x06
#define VFindNode 0x07
#define VFetchNode 0x08
#define VSendNode 0x09
#define VSetSeen 0x0A
#define VOnlineState 0x0B

//vault ID's
/*
#define VIDUnk1 0x00 //A Integer, Always seen 0xC0AB3041 (integer)
#define VIDNodeType 0x01 //A Integer with the Node Type (integer)
#define VIDUniqueId 0x02 //A vault node Id, VMGR id (integer)
#define VIDIntList 0x0A //A list of integers (creatablestream)
#define VID
#define VIDFolder 0x17 //The Vault folder name (strign)
*/

//vault tasks
#define TCreatePlayer 0x01
#define TDeletePlayer 0x02
#define TGetPlayerList 0x03
#define TCreateNeighborhood 0x04
#define TJoinNeighborhood 0x05
#define TSetAgePublic 0x06
#define TIncPlayerOnlineTime 0x07
#define TEnablePlayer 0x08
#define TRegisterOwnedAge 0x09
#define TUnRegisterOwnedAge 0x0A
#define TRegisterVisitAge 0x0B
#define TUnRegisterVisitAge 0x0C
#define TFriendInvite 0x0D

//data types
#define DAgeLinkStruct         0x02BF
#define DCreatableGenericValue 0x0387
#define DCreatableStream       0x0389
#define DServerGuid            0x034D
#define DVaultNodeRef          0x0438
//tpots
#define DVaultNodeRef2         0x0439
#define DVaultNode             0x0439
//tpots
#define DVaultNode2            0x043A

//sub data types
#define DInteger 0x00 //(4 bytes) integer
#define DFloat 0x01 //(4 bytes) float
#define DBool 0x02 //(1 byte) byte (boolean value)
#define DUruString 0x03 //an (32 bytes STRING)
#define DPlKey 0x04 //uruobject
#define DStruct 0x05 //a list of variables (an struct)
#define DCreatable 0x06 //arghhah!! **
#define DTimestamp 0x07 //a Timestamp (I think that is in double format) **
#define DTime 0x08 // the timestamp and the microseconds (8 bytes)
#define DByte 0x09 //a byte
#define DShort 0x0A //a short integer (2 bytes)
#define DAgeTimeOfDay 0x0B //I bet that is also timestamp+microseconds (8 bytes) **
#define DVector3 0x32 //Three floats (4+4+4 bytes)
#define DPoint3 0x33 //Three floats (4+4+4 bytes)
#define DQuaternion 0x36 //Four floats (4+4+4+4 bytes)
#define DRGB8 0x37 //3 bytes (RBG color)

#endif
