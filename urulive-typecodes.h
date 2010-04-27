/*
 *
 * UruLive typecodes (from client version 9.847)
 *
 */

/* $Id: $ */

#ifndef _URULIVE_TYPECODES_H_
#define _URULIVE_TYPECODES_H_

#define live_plSceneNode 0x0000
#define live_plSceneObject 0x0001
#define live_hsKeyedObject 0x0002
#define live_plBitmap 0x0003
#define live_plMipmap 0x0004
#define live_plCubicEnvironmap 0x0005
#define live_plLayer 0x0006
#define live_hsGMaterial 0x0007
#define live_plParticleSystem 0x0008
#define live_plParticleEffect 0x0009
#define live_plParticleCollisionEffectBeat 0x000A
#define live_plParticleFadeVolumeEffect 0x000B
#define live_plBoundInterface 0x000C
#define live_plRenderTarget 0x000D
#define live_plCubicRenderTarget 0x000E
#define live_plCubicRenderTargetModifier 0x000F
#define live_plObjInterface 0x0010
#define live_plAudioInterface 0x0011
#define live_plAudible 0x0012
#define live_plAudibleNull 0x0013
#define live_plWinAudible 0x0014
#define live_plCoordinateInterface 0x0015
#define live_plDrawInterface 0x0016
#define live_plDrawable 0x0017
#define live_plDrawableMesh 0x0018
#define live_plDrawableIce 0x0019
#define live_plPhysical 0x001A
#define live_plPhysicalMesh 0x001B
#define live_plSimulationInterface 0x001C
#define live_plCameraModifier 0x001D
#define live_plModifier 0x001E
#define live_plSingleModifier 0x001F
#define live_plSimpleModifier 0x0020
#define live_pfSecurePreloader 0x0021
#define live_UNUSED_plRandomTMModifier 0x0022
#define live_plInterestingModifier 0x0023
#define live_plDetectorModifier 0x0024
#define live_plSimplePhysicalMesh 0x0025
#define live_plCompoundPhysicalMesh 0x0026
#define live_plMultiModifier 0x0027
#define live_plSynchedObject 0x0028
#define live_plSoundBuffer 0x0029
#define live_UNUSED_plAliasModifier 0x002A
#define live_plPickingDetector 0x002B
#define live_plCollisionDetector 0x002C
#define live_plLogicModifier 0x002D
#define live_plConditionalObject 0x002E
#define live_plANDConditionalObject 0x002F
#define live_plORConditionalObject 0x0030
#define live_plPickedConditionalObject 0x0031
#define live_plActivatorConditionalObject 0x0032
#define live_plTimerCallbackManager 0x0033
#define live_plKeyPressConditionalObject 0x0034
#define live_plAnimationEventConditionalObject 0x0035
#define live_plControlEventConditionalObject 0x0036
#define live_plObjectInBoxConditionalObject 0x0037
#define live_plLocalPlayerInBoxConditionalObject 0x0038
#define live_plObjectIntersectPlaneConditionalObject 0x0039
#define live_plLocalPlayerIntersectPlaneConditionalObject 0x003A
#define live_plPortalDrawable 0x003B
#define live_plPortalPhysical 0x003C
#define live_plSpawnModifier 0x003D
#define live_plFacingConditionalObject 0x003E
#define live_plPXPhysical 0x003F
#define live_plViewFaceModifier 0x0040
#define live_plLayerInterface 0x0041
#define live_plLayerWrapper 0x0042
#define live_plLayerAnimation 0x0043
#define live_plLayerDepth 0x0044
#define live_plLayerMovie 0x0045
#define live_plLayerBink 0x0046
#define live_plLayerAVI 0x0047
#define live_plSound 0x0048
#define live_plWin32Sound 0x0049
#define live_plLayerOr 0x004A
#define live_plAudioSystem 0x004B
#define live_plDrawableSpans 0x004C
#define live_UNUSED_plDrawablePatchSet 0x004D
#define live_plInputManager 0x004E
#define live_plLogicModBase 0x004F
#define live_plFogEnvironment 0x0050
#define live_plNetApp 0x0051
#define live_plNetClientMgr 0x0052
#define live_pl2WayWinAudible 0x0053
#define live_plLightInfo 0x0054
#define live_plDirectionalLightInfo 0x0055
#define live_plOmniLightInfo 0x0056
#define live_plSpotLightInfo 0x0057
#define live_plLightSpace 0x0058
#define live_plNetClientApp 0x0059
#define live_plNetServerApp 0x005A
#define live_plClient 0x005B
#define live_UNUSED_plCompoundTMModifier 0x005C
#define live_plCameraBrain 0x005D
#define live_plCameraBrain_Default 0x005E
#define live_plCameraBrain_Drive 0x005F
#define live_plCameraBrain_Fixed 0x0060
#define live_plCameraBrain_FixedPan 0x0061
#define live_pfGUIClickMapCtrl 0x0062
#define live_plListener 0x0063
#define live_plAvatarMod 0x0064
#define live_plAvatarAnim 0x0065
#define live_plAvatarAnimMgr 0x0066
#define live_plOccluder 0x0067
#define live_plMobileOccluder 0x0068
#define live_plLayerShadowBase 0x0069
#define live_plLimitedDirLightInfo 0x006A
#define live_plAGAnim 0x006B
#define live_plAGModifier 0x006C
#define live_plAGMasterMod 0x006D
#define live_plCameraBrain_Avatar 0x006E
#define live_plCameraRegionDetector 0x006F
#define live_plCameraBrain_FP 0x0070
#define live_plLineFollowMod 0x0071
#define live_plLightModifier 0x0072
#define live_plOmniModifier 0x0073
#define live_plSpotModifier 0x0074
#define live_plLtdDirModifier 0x0075
#define live_plSeekPointMod 0x0076
#define live_plOneShotMod 0x0077
#define live_plRandomCommandMod 0x0078
#define live_plRandomSoundMod 0x0079
#define live_plPostEffectMod 0x007A
#define live_plObjectInVolumeDetector 0x007B
#define live_plResponderModifier 0x007C
#define live_plAxisAnimModifier 0x007D
#define live_plLayerLightBase 0x007E
#define live_plFollowMod 0x007F
#define live_plTransitionMgr 0x0080
#define live_UNUSED___plInventoryMod 0x0081
#define live_UNUSED___plInventoryObjMod 0x0082
#define live_plLinkEffectsMgr 0x0083
#define live_plWin32StreamingSound 0x0084
#define live_UNUSED___plPythonMod 0x0085
#define live_plActivatorActivatorConditionalObject 0x0086
#define live_plSoftVolume 0x0087
#define live_plSoftVolumeSimple 0x0088
#define live_plSoftVolumeComplex 0x0089
#define live_plSoftVolumeUnion 0x008A
#define live_plSoftVolumeIntersect 0x008B
#define live_plSoftVolumeInvert 0x008C
#define live_plWin32LinkSound 0x008D
#define live_plLayerLinkAnimation 0x008E
#define live_plArmatureMod 0x008F
#define live_plCameraBrain_Freelook 0x0090
#define live_plHavokConstraintsMod 0x0091
#define live_plHingeConstraintMod 0x0092
#define live_plWheelConstraintMod 0x0093
#define live_plStrongSpringConstraintMod 0x0094
#define live_plArmatureLODMod 0x0095
#define live_plWin32StaticSound 0x0096
#define live_pfGameGUIMgr 0x0097
#define live_pfGUIDialogMod 0x0098
#define live_plCameraBrain1 0x0099
#define live_plVirtualCam1 0x009A
#define live_plCameraModifier1 0x009B
#define live_plCameraBrain1_Drive 0x009C
#define live_plCameraBrain1_POA 0x009D
#define live_plCameraBrain1_Avatar 0x009E
#define live_plCameraBrain1_Fixed 0x009F
#define live_plCameraBrain1_POAFixed 0x00A0
#define live_pfGUIButtonMod 0x00A1
#define live_plPythonFileMod 0x00A2
#define live_pfGUIControlMod 0x00A3
#define live_plExcludeRegionModifier 0x00A4
#define live_pfGUIDraggableMod 0x00A5
#define live_plVolumeSensorConditionalObject 0x00A6
#define live_plVolActivatorConditionalObject 0x00A7
#define live_plMsgForwarder 0x00A8
#define live_plBlower 0x00A9
#define live_pfGUIListBoxMod 0x00AA
#define live_pfGUITextBoxMod 0x00AB
#define live_pfGUIEditBoxMod 0x00AC
#define live_plDynamicTextMap 0x00AD
#define live_plSittingModifier 0x00AE
#define live_pfGUIUpDownPairMod 0x00AF
#define live_pfGUIValueCtrl 0x00B0
#define live_pfGUIKnobCtrl 0x00B1
#define live_plAvLadderMod 0x00B2
#define live_plCameraBrain1_FirstPerson 0x00B3
#define live_plCloneSpawnModifier 0x00B4
#define live_plClothingItem 0x00B5
#define live_plClothingOutfit 0x00B6
#define live_plClothingBase 0x00B7
#define live_plClothingMgr 0x00B8
#define live_pfGUIDragBarCtrl 0x00B9
#define live_pfGUICheckBoxCtrl 0x00BA
#define live_pfGUIRadioGroupCtrl 0x00BB
#define live_pfPlayerBookMod 0x00BC
#define live_pfGUIDynDisplayCtrl 0x00BD
#define live_UNUSED_plLayerProject 0x00BE
#define live_plInputInterfaceMgr 0x00BF
#define live_plRailCameraMod 0x00C0
#define live_plMultistageBehMod 0x00C1
#define live_plCameraBrain1_Circle 0x00C2
#define live_plParticleWindEffect 0x00C3
#define live_plAnimEventModifier 0x00C4
#define live_plAutoProfile 0x00C5
#define live_pfGUISkin 0x00C6
#define live_plAVIWriter 0x00C7
#define live_plParticleCollisionEffect 0x00C8
#define live_plParticleCollisionEffectDie 0x00C9
#define live_plParticleCollisionEffectBounce 0x00CA
#define live_plInterfaceInfoModifier 0x00CB
#define live_plSharedMesh 0x00CC
#define live_plArmatureEffectsMgr 0x00CD
#define live_pfMarkerMgr 0x00CE
#define live_plVehicleModifier 0x00CF
#define live_plParticleLocalWind 0x00D0
#define live_plParticleUniformWind 0x00D1
#define live_plInstanceDrawInterface 0x00D2
#define live_plShadowMaster 0x00D3
#define live_plShadowCaster 0x00D4
#define live_plPointShadowMaster 0x00D5
#define live_plDirectShadowMaster 0x00D6
#define live_plSDLModifier 0x00D7
#define live_plPhysicalSDLModifier 0x00D8
#define live_plClothingSDLModifier 0x00D9
#define live_plAvatarSDLModifier 0x00DA
#define live_plAGMasterSDLModifier 0x00DB
#define live_plPythonSDLModifier 0x00DC
#define live_plLayerSDLModifier 0x00DD
#define live_plAnimTimeConvertSDLModifier 0x00DE
#define live_plResponderSDLModifier 0x00DF
#define live_plSoundSDLModifier 0x00E0
#define live_plResManagerHelper 0x00E1
#define live_plAvatarPhysicalSDLModifier 0x00E2
#define live_plArmatureEffect 0x00E3
#define live_plArmatureEffectFootSound 0x00E4
#define live_plEAXListenerMod 0x00E5
#define live_plDynaDecalMgr 0x00E6
#define live_plObjectInVolumeAndFacingDetector 0x00E7
#define live_plDynaFootMgr 0x00E8
#define live_plDynaRippleMgr 0x00E9
#define live_plDynaBulletMgr 0x00EA
#define live_plDecalEnableMod 0x00EB
#define live_plPrintShape 0x00EC
#define live_plDynaPuddleMgr 0x00ED
#define live_pfGUIMultiLineEditCtrl 0x00EE
#define live_plLayerAnimationBase 0x00EF
#define live_plLayerSDLAnimation 0x00F0
#define live_plATCAnim 0x00F1
#define live_plAgeGlobalAnim 0x00F2
#define live_plSubworldRegionDetector 0x00F3
#define live_plAvatarMgr 0x00F4
#define live_plNPCSpawnMod 0x00F5
#define live_plActivePrintShape 0x00F6
#define live_plExcludeRegionSDLModifier 0x00F7
#define live_plLOSDispatch 0x00F8
#define live_plDynaWakeMgr 0x00F9
#define live_plSimulationMgr 0x00FA
#define live_plWaveSet7 0x00FB
#define live_plPanicLinkRegion 0x00FC
#define live_plWin32GroupedSound 0x00FD
#define live_plFilterCoordInterface 0x00FE
#define live_plStereizer 0x00FF
#define live_plCCRMgr 0x0100
#define live_plCCRSpecialist 0x0101
#define live_plCCRSeniorSpecialist 0x0102
#define live_plCCRShiftSupervisor 0x0103
#define live_plCCRGameOperator 0x0104
#define live_plShader 0x0105
#define live_plDynamicEnvMap 0x0106
#define live_plSimpleRegionSensor 0x0107
#define live_plMorphSequence 0x0108
#define live_plEmoteAnim 0x0109
#define live_plDynaRippleVSMgr 0x010A
#define live_UNUSED_plWaveSet6 0x010B
#define live_pfGUIProgressCtrl 0x010C
#define live_plMaintainersMarkerModifier 0x010D
#define live_plMorphSequenceSDLMod 0x010E
#define live_plMorphDataSet 0x010F
#define live_plHardRegion 0x0110
#define live_plHardRegionPlanes 0x0111
#define live_plHardRegionComplex 0x0112
#define live_plHardRegionUnion 0x0113
#define live_plHardRegionIntersect 0x0114
#define live_plHardRegionInvert 0x0115
#define live_plVisRegion 0x0116
#define live_plVisMgr 0x0117
#define live_plRegionBase 0x0118
#define live_pfGUIPopUpMenu 0x0119
#define live_pfGUIMenuItem 0x011A
#define live_plCoopCoordinator 0x011B
#define live_plFont 0x011C
#define live_plFontCache 0x011D
#define live_plRelevanceRegion 0x011E
#define live_plRelevanceMgr 0x011F
#define live_pfJournalBook 0x0120
#define live_plLayerTargetContainer 0x0121
#define live_plImageLibMod 0x0122
#define live_plParticleFlockEffect 0x0123
#define live_plParticleSDLMod 0x0124
#define live_plAgeLoader 0x0125
#define live_plWaveSetBase 0x0126
#define live_plPhysicalSndGroup 0x0127
#define live_pfBookData 0x0128
#define live_plDynaTorpedoMgr 0x0129
#define live_plDynaTorpedoVSMgr 0x012A
#define live_plClusterGroup 0x012B
#define live_plGameMarkerModifier 0x012C
#define live_plLODMipmap 0x012D
#define live_plSwimDetector 0x012E
#define live_plFadeOpacityMod 0x012F
#define live_plFadeOpacityLay 0x0130
#define live_plDistOpacityMod 0x0131
#define live_plArmatureModBase 0x0132
#define live_plSwimRegionInterface 0x0133
#define live_plSwimCircularCurrentRegion 0x0134
#define live_plParticleFollowSystemEffect 0x0135
#define live_plSwimStraightCurrentRegion 0x0136
#define live_pfObjectFlocker 0x0137
#define live_plGrassShaderMod 0x0138
#define live_plDynamicCamMap 0x0139
#define live_plRidingAnimatedPhysicalDetector 0x013A
#define live_plVolumeSensorConditionalObjectNoArbitration 0x013B

#define live_plObjRefMsg 0x0200
#define live_plNodeRefMsg 0x0201
#define live_plMessage 0x0202
#define live_plRefMsg 0x0203
#define live_plGenRefMsg 0x0204
#define live_plTimeMsg 0x0205
#define live_plAnimCmdMsg 0x0206
#define live_plParticleUpdateMsg 0x0207
#define live_plLayRefMsg 0x0208
#define live_plMatRefMsg 0x0209
#define live_plCameraMsg 0x020A
#define live_plInputEventMsg 0x020B
#define live_plKeyEventMsg 0x020C
#define live_plMouseEventMsg 0x020D
#define live_plEvalMsg 0x020E
#define live_plTransformMsg 0x020F
#define live_plControlEventMsg 0x0210
#define live_plVaultCCRNode 0x0211
#define live_plLOSRequestMsg 0x0212
#define live_plLOSHitMsg 0x0213
#define live_plSingleModMsg 0x0214
#define live_plMultiModMsg 0x0215
#define live_plAvatarPhysicsEnableCallbackMsg 0x0216
#define live_plMemberUpdateMsg 0x0217
#define live_plNetMsgPagingRoom 0x0218
#define live_plActivatorMsg 0x0219
#define live_plDispatch 0x021A
#define live_plReceiver 0x021B
#define live_plMeshRefMsg 0x021C
#define live_hsGRenderProcs 0x021D
#define live_hsSfxAngleFade 0x021E
#define live_hsSfxDistFade 0x021F
#define live_hsSfxDistShade 0x0220
#define live_hsSfxGlobalShade 0x0221
#define live_hsSfxIntenseAlpha 0x0222
#define live_hsSfxObjDistFade 0x0223
#define live_hsSfxObjDistShade 0x0224
#define live_hsDynamicValue 0x0225
#define live_hsDynamicScalar 0x0226
#define live_hsDynamicColorRGBA 0x0227
#define live_hsDynamicMatrix33 0x0228
#define live_hsDynamicMatrix44 0x0229
#define live_plOmniSqApplicator 0x022A
#define live_plPreResourceMsg 0x022B
#define live_UNUSED_hsDynamicColorRGBA 0x022C
#define live_UNUSED_hsDynamicMatrix33 0x022D
#define live_UNUSED_hsDynamicMatrix44 0x022E
#define live_plController 0x022F
#define live_plLeafController 0x0230
#define live_plCompoundController 0x0231
#define live_UNUSED_plRotController 0x0232
#define live_UNUSED_plPosController 0x0233
#define live_UNUSED_plScalarController 0x0234
#define live_UNUSED_plPoint3Controller 0x0235
#define live_UNUSED_plScaleValueController 0x0236
#define live_UNUSED_plQuatController 0x0237
#define live_UNUSED_plMatrix33Controller 0x0238
#define live_UNUSED_plMatrix44Controller 0x0239
#define live_UNUSED_plEaseController 0x023A
#define live_UNUSED_plSimpleScaleController 0x023B
#define live_UNUSED_plSimpleRotController 0x023C
#define live_plCompoundRotController 0x023D
#define live_UNUSED_plSimplePosController 0x023E
#define live_plCompoundPosController 0x023F
#define live_plTMController 0x0240
#define live_hsFogControl 0x0241
#define live_plIntRefMsg 0x0242
#define live_plCollisionReactor 0x0243
#define live_plCorrectionMsg 0x0244
#define live_plPhysicalModifier 0x0245
#define live_plPickedMsg 0x0246
#define live_plCollideMsg 0x0247
#define live_plTriggerMsg 0x0248
#define live_plInterestingModMsg 0x0249
#define live_plDebugKeyEventMsg 0x024A
#define live_plPhysicalProperties_DEAD 0x024B
#define live_plSimplePhys 0x024C
#define live_plMatrixUpdateMsg 0x024D
#define live_plCondRefMsg 0x024E
#define live_plTimerCallbackMsg 0x024F
#define live_plEventCallbackMsg 0x0250
#define live_plSpawnModMsg 0x0251
#define live_plSpawnRequestMsg 0x0252
#define live_plLoadCloneMsg 0x0253
#define live_plEnableMsg 0x0254
#define live_plWarpMsg 0x0255
#define live_plAttachMsg 0x0256
#define live_pfConsole 0x0257
#define live_plRenderMsg 0x0258
#define live_plAnimTimeConvert 0x0259
#define live_plSoundMsg 0x025A
#define live_plInterestingPing 0x025B
#define live_plNodeCleanupMsg 0x025C
#define live_plSpaceTree 0x025D
#define live_plNetMessage 0x025E
#define live_plNetMsgJoinReq 0x025F
#define live_plNetMsgJoinAck 0x0260
#define live_plNetMsgLeave 0x0261
#define live_plNetMsgPing 0x0262
#define live_plNetMsgRoomsList 0x0263
#define live_plNetMsgGroupOwner 0x0264
#define live_plNetMsgGameStateRequest 0x0265
#define live_plNetMsgSessionReset 0x0266
#define live_plNetMsgOmnibus 0x0267
#define live_plNetMsgObject 0x0268
#define live_plCCRInvisibleMsg 0x0269
#define live_plLinkInDoneMsg 0x026A
#define live_plNetMsgGameMessage 0x026B
#define live_plNetMsgStream 0x026C
#define live_plAudioSysMsg 0x026D
#define live_plDispatchBase 0x026E
#define live_plServerReplyMsg 0x026F
#define live_plDeviceRecreateMsg 0x0270
#define live_plNetMsgStreamHelper 0x0271
#define live_plNetMsgObjectHelper 0x0272
#define live_plIMouseXEventMsg 0x0273
#define live_plIMouseYEventMsg 0x0274
#define live_plIMouseBEventMsg 0x0275
#define live_plLogicTriggerMsg 0x0276
#define live_plPipeline 0x0277
#define live_plDXPipeline 0x0278
#define live_plNetMsgVoice 0x0279
#define live_plLightRefMsg 0x027A
#define live_plNetMsgStreamedObject 0x027B
#define live_plNetMsgSharedState 0x027C
#define live_plNetMsgTestAndSet 0x027D
#define live_plNetMsgGetSharedState 0x027E
#define live_plSharedStateMsg 0x027F
#define live_plNetGenericServerTask 0x0280
#define live_plNetClientMgrMsg 0x0281
#define live_plLoadAgeMsg 0x0282
#define live_plMessageWithCallbacks 0x0283
#define live_plClientMsg 0x0284
#define live_plClientRefMsg 0x0285
#define live_plNetMsgObjStateRequest 0x0286
#define live_plCCRPetitionMsg 0x0287
#define live_plVaultCCRInitializationTask 0x0288
#define live_plNetServerMsg 0x0289
#define live_plNetServerMsgWithContext 0x028A
#define live_plNetServerMsgRegisterServer 0x028B
#define live_plNetServerMsgUnregisterServer 0x028C
#define live_plNetServerMsgStartProcess 0x028D
#define live_plNetServerMsgRegisterProcess 0x028E
#define live_plNetServerMsgUnregisterProcess 0x028F
#define live_plNetServerMsgFindProcess 0x0290
#define live_plNetServerMsgProcessFound 0x0291
#define live_plNetMsgRoutingInfo 0x0292
#define live_plNetServerSessionInfo 0x0293
#define live_plSimulationMsg 0x0294
#define live_plSimulationSynchMsg 0x0295
#define live_plHKSimulationSynchMsg 0x0296
#define live_plAvatarMsg 0x0297
#define live_plAvTaskMsg 0x0298
#define live_plAvSeekMsg 0x0299
#define live_plAvOneShotMsg 0x029A
#define live_plSatisfiedMsg 0x029B
#define live_plNetMsgObjectListHelper 0x029C
#define live_plNetMsgObjectUpdateFilter 0x029D
#define live_plProxyDrawMsg 0x029E
#define live_plSelfDestructMsg 0x029F
#define live_plSimInfluenceMsg 0x02A0
#define live_plForceMsg 0x02A1
#define live_plOffsetForceMsg 0x02A2
#define live_plTorqueMsg 0x02A3
#define live_plImpulseMsg 0x02A4
#define live_plOffsetImpulseMsg 0x02A5
#define live_plAngularImpulseMsg 0x02A6
#define live_plDampMsg 0x02A7
#define live_plShiftMassMsg 0x02A8
#define live_plSimStateMsg 0x02A9
#define live_plFreezeMsg 0x02AA
#define live_plEventGroupMsg 0x02AB
#define live_plSuspendEventMsg 0x02AC
#define live_plNetMsgMembersListReq 0x02AD
#define live_plNetMsgMembersList 0x02AE
#define live_plNetMsgMemberInfoHelper 0x02AF
#define live_plNetMsgMemberListHelper 0x02B0
#define live_plNetMsgMemberUpdate 0x02B1
#define live_plNetMsgServerToClient 0x02B2
#define live_plNetMsgCreatePlayer 0x02B3
#define live_plNetMsgAuthenticateHello 0x02B4
#define live_plNetMsgAuthenticateChallenge 0x02B5
#define live_plConnectedToVaultMsg 0x02B6
#define live_plCCRCommunicationMsg 0x02B7
#define live_plNetMsgInitialAgeStateSent 0x02B8
#define live_plInitialAgeStateLoadedMsg 0x02B9
#define live_plNetServerMsgFindServerBase 0x02BA
#define live_plNetServerMsgFindServerReplyBase 0x02BB
#define live_plNetServerMsgFindAuthServer 0x02BC
#define live_plNetServerMsgFindAuthServerReply 0x02BD
#define live_plNetServerMsgFindVaultServer 0x02BE
#define live_plNetServerMsgFindVaultServerReply 0x02BF
#define live_plAvTaskSeekDoneMsg 0x02C0
#define live_plNCAgeJoinerMsg 0x02C1
#define live_plNetServerMsgVaultTask 0x02C2
#define live_plNetMsgVaultTask 0x02C3
#define live_plAgeLinkStruct 0x02C4
#define live_plVaultAgeInfoNode 0x02C5
#define live_plNetMsgStreamableHelper 0x02C6
#define live_plNetMsgReceiversListHelper 0x02C7
#define live_plNetMsgListenListUpdate 0x02C8
#define live_plNetServerMsgPing 0x02C9
#define live_plNetMsgAlive 0x02CA
#define live_plNetMsgTerminated 0x02CB
#define live_plSDLModifierMsg 0x02CC
#define live_plNetMsgSDLState 0x02CD
#define live_plNetServerMsgSessionReset 0x02CE
#define live_plCCRBanLinkingMsg 0x02CF
#define live_plCCRSilencePlayerMsg 0x02D0
#define live_plRenderRequestMsg 0x02D1
#define live_plRenderRequestAck 0x02D2
#define live_plNetMember 0x02D3
#define live_plNetGameMember 0x02D4
#define live_plNetTransportMember 0x02D5
#define live_plConvexVolume 0x02D6
#define live_plParticleGenerator 0x02D7
#define live_plSimpleParticleGenerator 0x02D8
#define live_plParticleEmitter 0x02D9
#define live_plAGChannel 0x02DA
#define live_plMatrixChannel 0x02DB
#define live_plMatrixTimeScale 0x02DC
#define live_plMatrixBlend 0x02DD
#define live_plMatrixControllerChannel 0x02DE
#define live_plQuatPointCombine 0x02DF
#define live_plPointChannel 0x02E0
#define live_plPointConstant 0x02E1
#define live_plPointBlend 0x02E2
#define live_plQuatChannel 0x02E3
#define live_plQuatConstant 0x02E4
#define live_plQuatBlend 0x02E5
#define live_plLinkToAgeMsg 0x02E6
#define live_plPlayerPageMsg 0x02E7
#define live_plCmdIfaceModMsg 0x02E8
#define live_plNetServerMsgPlsUpdatePlayer 0x02E9
#define live_plListenerMsg 0x02EA
#define live_plAnimPath 0x02EB
#define live_plClothingUpdateBCMsg 0x02EC
#define live_plNotifyMsg 0x02ED
#define live_plFakeOutMsg 0x02EE
#define live_plCursorChangeMsg 0x02EF
#define live_plNodeChangeMsg 0x02F0
#define live_UNUSED_plAvEnableMsg 0x02F1
#define live_plLinkCallbackMsg 0x02F2
#define live_plTransitionMsg 0x02F3
#define live_plConsoleMsg 0x02F4
#define live_plVolumeIsect 0x02F5
#define live_plSphereIsect 0x02F6
#define live_plConeIsect 0x02F7
#define live_plCylinderIsect 0x02F8
#define live_plParallelIsect 0x02F9
#define live_plConvexIsect 0x02FA
#define live_plComplexIsect 0x02FB
#define live_plUnionIsect 0x02FC
#define live_plIntersectionIsect 0x02FD
#define live_plModulator 0x02FE
#define live_UNUSED___plInventoryMsg 0x02FF
#define live_plLinkEffectsTriggerMsg 0x0300
#define live_plLinkEffectBCMsg 0x0301
#define live_plResponderEnableMsg 0x0302
#define live_plNetServerMsgHello 0x0303
#define live_plNetServerMsgHelloReply 0x0304
#define live_plNetServerMember 0x0305
#define live_plResponderMsg 0x0306
#define live_plOneShotMsg 0x0307
#define live_plVaultAgeInfoListNode 0x0308
#define live_plNetServerMsgServerRegistered 0x0309
#define live_plPointTimeScale 0x030A
#define live_plPointControllerChannel 0x030B
#define live_plQuatTimeScale 0x030C
#define live_plAGApplicator 0x030D
#define live_plMatrixChannelApplicator 0x030E
#define live_plPointChannelApplicator 0x030F
#define live_plLightDiffuseApplicator 0x0310
#define live_plLightAmbientApplicator 0x0311
#define live_plLightSpecularApplicator 0x0312
#define live_plOmniApplicator 0x0313
#define live_plQuatChannelApplicator 0x0314
#define live_plScalarChannel 0x0315
#define live_plScalarTimeScale 0x0316
#define live_plScalarBlend 0x0317
#define live_plScalarControllerChannel 0x0318
#define live_plScalarChannelApplicator 0x0319
#define live_plSpotInnerApplicator 0x031A
#define live_plSpotOuterApplicator 0x031B
#define live_plNetServerMsgPlsRoutableMsg 0x031C
#define live__UNUSED_plPuppetBrainMsg 0x031D
#define live_plATCEaseCurve 0x031E
#define live_plConstAccelEaseCurve 0x031F
#define live_plSplineEaseCurve 0x0320
#define live_plVaultAgeInfoInitializationTask 0x0321
#define live_pfGameGUIMsg 0x0322
#define live_plNetServerMsgVaultRequestGameState 0x0323
#define live_plNetServerMsgVaultGameState 0x0324
#define live_plNetServerMsgVaultGameStateSave 0x0325
#define live_plNetServerMsgVaultGameStateSaved 0x0326
#define live_plNetServerMsgVaultGameStateLoad 0x0327
#define live_plNetClientTask 0x0328
#define live_plNetMsgSDLStateBCast 0x0329
#define live_plReplaceGeometryMsg 0x032A
#define live_plNetServerMsgExitProcess 0x032B
#define live_plNetServerMsgSaveGameState 0x032C
#define live_plDniCoordinateInfo 0x032D
#define live_plNetMsgGameMessageDirected 0x032E
#define live_plLinkOutUnloadMsg 0x032F
#define live_plScalarConstant 0x0330
#define live_plMatrixConstant 0x0331
#define live_plAGCmdMsg 0x0332
#define live_plParticleTransferMsg 0x0333
#define live_plParticleKillMsg 0x0334
#define live_plExcludeRegionMsg 0x0335
#define live_plOneTimeParticleGenerator 0x0336
#define live_plParticleApplicator 0x0337
#define live_plParticleLifeMinApplicator 0x0338
#define live_plParticleLifeMaxApplicator 0x0339
#define live_plParticlePPSApplicator 0x033A
#define live_plParticleAngleApplicator 0x033B
#define live_plParticleVelMinApplicator 0x033C
#define live_plParticleVelMaxApplicator 0x033D
#define live_plParticleScaleMinApplicator 0x033E
#define live_plParticleScaleMaxApplicator 0x033F
#define live_plDynamicTextMsg 0x0340
#define live_plCameraTargetFadeMsg 0x0341
#define live_plAgeLoadedMsg 0x0342
#define live_plPointControllerCacheChannel 0x0343
#define live_plScalarControllerCacheChannel 0x0344
#define live_plLinkEffectsTriggerPrepMsg 0x0345
#define live_plLinkEffectPrepBCMsg 0x0346
#define live_plAvatarInputStateMsg 0x0347
#define live_plAgeInfoStruct 0x0348
#define live_plSDLNotificationMsg 0x0349
#define live_plNetClientConnectAgeVaultTask 0x034A
#define live_plLinkingMgrMsg 0x034B
#define live_plVaultNotifyMsg 0x034C
#define live_plPlayerInfo 0x034D
#define live_plSwapSpansRefMsg 0x034E
#define live_pfKI 0x034F
#define live_plDISpansMsg 0x0350
#define live_plNetMsgCreatableHelper 0x0351
#define live_plCreatableUuid 0x0352
#define live_plNetMsgRequestMyVaultPlayerList 0x0353
#define live_plDelayedTransformMsg 0x0354
#define live_plSuperVNodeMgrInitTask 0x0355
#define live_plElementRefMsg 0x0356
#define live_plClothingMsg 0x0357
#define live_plEventGroupEnableMsg 0x0358
#define live_pfGUINotifyMsg 0x0359
#define live_UNUSED_plAvBrain 0x035A
#define live_plArmatureBrain 0x035B
#define live_plAvBrainHuman 0x035C
#define live_plAvBrainCritter 0x035D
#define live_plAvBrainDrive 0x035E
#define live_plAvBrainSample 0x035F
#define live_plAvBrainGeneric 0x0360
#define live_plPreloaderMsg 0x0361
#define live_plAvBrainLadder 0x0362
#define live_plInputIfaceMgrMsg 0x0363
#define live_pfKIMsg 0x0364
#define live_plRemoteAvatarInfoMsg 0x0365
#define live_plMatrixDelayedCorrectionApplicator 0x0366
#define live_plAvPushBrainMsg 0x0367
#define live_plAvPopBrainMsg 0x0368
#define live_plRoomLoadNotifyMsg 0x0369
#define live_plAvTask 0x036A
#define live_plAvAnimTask 0x036B
#define live_plAvSeekTask 0x036C
#define live_plNetCommAuthConnectedMsg 0x036D
#define live_plAvOneShotTask 0x036E
#define live_UNUSED_plAvEnableTask 0x036F
#define live_plAvTaskBrain 0x0370
#define live_plAnimStage 0x0371
#define live_plNetClientMember 0x0372
#define live_plNetClientCommTask 0x0373
#define live_plNetServerMsgAuthRequest 0x0374
#define live_plNetServerMsgAuthReply 0x0375
#define live_plNetClientCommAuthTask 0x0376
#define live_plClientGuid 0x0377
#define live_plNetMsgVaultPlayerList 0x0378
#define live_plNetMsgSetMyActivePlayer 0x0379
#define live_plNetServerMsgRequestAccountPlayerList 0x037A
#define live_plNetServerMsgAccountPlayerList 0x037B
#define live_plNetMsgPlayerCreated 0x037C
#define live_plNetServerMsgVaultCreatePlayer 0x037D
#define live_plNetServerMsgVaultPlayerCreated 0x037E
#define live_plNetMsgFindAge 0x037F
#define live_plNetMsgFindAgeReply 0x0380
#define live_plNetClientConnectPrepTask 0x0381
#define live_plNetClientAuthTask 0x0382
#define live_plNetClientGetPlayerVaultTask 0x0383
#define live_plNetClientSetActivePlayerTask 0x0384
#define live_plNetClientFindAgeTask 0x0385
#define live_plNetClientLeaveTask 0x0386
#define live_plNetClientJoinTask 0x0387
#define live_plNetClientCalibrateTask 0x0388
#define live_plNetMsgDeletePlayer 0x0389
#define live_plNetServerMsgVaultDeletePlayer 0x038A
#define live_plNetCoreStatsSummary 0x038B
#define live_plCreatableGenericValue 0x038C
#define live_plCreatableListHelper 0x038D
#define live_plCreatableStream 0x038E
#define live_plAvBrainGenericMsg 0x038F
#define live_plAvTaskSeek 0x0390
#define live_plAGInstanceCallbackMsg 0x0391
#define live_plArmatureEffectMsg 0x0392
#define live_plArmatureEffectStateMsg 0x0393
#define live_plShadowCastMsg 0x0394
#define live_plBoundsIsect 0x0395
#define live_plResMgrHelperMsg 0x0396
#define live_plNetCommAuthMsg 0x0397
#define live_plNetCommFileListMsg 0x0398
#define live_plNetCommFileDownloadMsg 0x0399
#define live_plNetCommLinkToAgeMsg 0x039A
#define live_plNetCommPlayerListMsg 0x039B
#define live_plNetCommActivePlayerMsg 0x039C
#define live_plNetCommCreatePlayerMsg 0x039D
#define live_plNetCommDeletePlayerMsg 0x039E
#define live_plNetCommPublicAgeListMsg 0x039F
#define live_plNetCommPublicAgeMsg 0x03A0
#define live_plNetCommRegisterAgeMsg 0x03A1
#define live_plVaultAdminInitializationTask 0x03A2
#define live_plMultistageModMsg 0x03A3
#define live_plSoundVolumeApplicator 0x03A4
#define live_plCutter 0x03A5
#define live_plBulletMsg 0x03A6
#define live_plDynaDecalEnableMsg 0x03A7
#define live_plOmniCutoffApplicator 0x03A8
#define live_plArmatureUpdateMsg 0x03A9
#define live_plAvatarFootMsg 0x03AA
#define live_plNetOwnershipMsg 0x03AB
#define live_plNetMsgRelevanceRegions 0x03AC
#define live_plParticleFlockMsg 0x03AD
#define live_plAvatarBehaviorNotifyMsg 0x03AE
#define live_plATCChannel 0x03AF
#define live_plScalarSDLChannel 0x03B0
#define live_plLoadAvatarMsg 0x03B1
#define live_plAvatarSetTypeMsg 0x03B2
#define live_plNetMsgLoadClone 0x03B3
#define live_plNetMsgPlayerPage 0x03B4
#define live_plVNodeInitTask 0x03B5
#define live_plRippleShapeMsg 0x03B6
#define live_plEventManager 0x03B7
#define live_plVaultNeighborhoodInitializationTask 0x03B8
#define live_plNetServerMsgAgentRecoveryRequest 0x03B9
#define live_plNetServerMsgFrontendRecoveryRequest 0x03BA
#define live_plNetServerMsgBackendRecoveryRequest 0x03BB
#define live_plNetServerMsgAgentRecoveryData 0x03BC
#define live_plNetServerMsgFrontendRecoveryData 0x03BD
#define live_plNetServerMsgBackendRecoveryData 0x03BE
#define live_plSubWorldMsg 0x03BF
#define live_plMatrixDifferenceApp 0x03C0
#define live_plAvatarSpawnNotifyMsg 0x03C1

#define live_plVaultGameServerInitializationTask 0x0427
#define live_plNetClientFindDefaultAgeTask 0x0428
#define live_plVaultAgeNode 0x0429
#define live_plVaultAgeInitializationTask 0x042A
#define live_plSetListenerMsg 0x042B
#define live_plVaultSystemNode 0x042C
#define live_plAvBrainSwim 0x042D
#define live_plNetMsgVault 0x042E
#define live_plNetServerMsgVault 0x042F
#define live_plVaultTask 0x0430
#define live_plVaultConnectTask 0x0431
#define live_plVaultNegotiateManifestTask 0x0432
#define live_plVaultFetchNodesTask 0x0433
#define live_plVaultSaveNodeTask 0x0434
#define live_plVaultFindNodeTask 0x0435
#define live_plVaultAddNodeRefTask 0x0436
#define live_plVaultRemoveNodeRefTask 0x0437
#define live_plVaultSendNodeTask 0x0438
#define live_plVaultNotifyOperationCallbackTask 0x0439
#define live_plVNodeMgrInitializationTask 0x043A
#define live_plVaultPlayerInitializationTask 0x043B
#define live_plNetVaultServerInitializationTask 0x043C
#define live_plCommonNeighborhoodsInitTask 0x043D
#define live_plVaultNodeRef 0x043E
#define live_plVaultNode 0x043F
#define live_plVaultFolderNode 0x0440
#define live_plVaultImageNode 0x0441
#define live_plVaultTextNoteNode 0x0442
#define live_plVaultSDLNode 0x0443
#define live_plVaultAgeLinkNode 0x0444
#define live_plVaultChronicleNode 0x0445
#define live_plVaultPlayerInfoNode 0x0446
#define live_plVaultMgrNode 0x0447
#define live_plVaultPlayerNode 0x0448
#define live_plSynchEnableMsg 0x0449
#define live_plNetVaultServerNode 0x044A
#define live_plVaultAdminNode 0x044B
#define live_plVaultGameServerNode 0x044C
#define live_plVaultPlayerInfoListNode 0x044D
#define live_plAvatarStealthModeMsg 0x044E
#define live_plEventCallbackInterceptMsg 0x044F
#define live_plDynamicEnvMapMsg 0x0450
#define live_plClimbMsg 0x0451
#define live_plIfaceFadeAvatarMsg 0x0452
#define live_plAvBrainClimb 0x0453
#define live_plSharedMeshBCMsg 0x0454
#define live_plNetVoiceListMsg 0x0455
#define live_plSwimMsg 0x0456
#define live_plMorphDelta 0x0457
#define live_plMatrixControllerCacheChannel 0x0458
#define live_plVaultMarkerNode 0x0459
#define live_pfMarkerMsg 0x045A
#define live_plPipeResMakeMsg 0x045B
#define live_plPipeRTMakeMsg 0x045C
#define live_plPipeGeoMakeMsg 0x045D
#define live_plAvCoopMsg 0x045E
#define live_plAvBrainCoop 0x045F
#define live_plSimSuppressMsg 0x0460
#define live_plVaultMarkerListNode 0x0461
#define live_UNUSED_plAvTaskOrient 0x0462
#define live_plAgeBeginLoadingMsg 0x0463
#define live_plSetNetGroupIDMsg 0x0464
#define live_pfBackdoorMsg 0x0465
#define live_plAIMsg 0x0466
#define live_plAIBrainCreatedMsg 0x0467
#define live_plStateDataRecord 0x0468
#define live_plNetClientCommDeletePlayerTask 0x0469
#define live_plNetMsgSetTimeout 0x046A
#define live_plNetMsgActivePlayerSet 0x046B
#define live_plNetClientCommSetTimeoutTask 0x046C
#define live_plNetRoutableMsgOmnibus 0x046D
#define live_plNetMsgGetPublicAgeList 0x046E
#define live_plNetMsgPublicAgeList 0x046F
#define live_plNetMsgCreatePublicAge 0x0470
#define live_plNetMsgPublicAgeCreated 0x0471
#define live_plNetServerMsgEnvelope 0x0472
#define live_plNetClientCommGetPublicAgeListTask 0x0473
#define live_plNetClientCommCreatePublicAgeTask 0x0474
#define live_plNetServerMsgPendingMsgs 0x0475
#define live_plNetServerMsgRequestPendingMsgs 0x0476
#define live_plDbInterface 0x0477
#define live_plDbProxyInterface 0x0478
#define live_plDBGenericSQLDB 0x0479
#define live_pfGameMgrMsg 0x047A
#define live_pfGameCliMsg 0x047B
#define live_pfGameCli 0x047C
#define live_pfGmTicTacToe 0x047D
#define live_pfGmHeek 0x047E
#define live_pfGmMarker 0x047F
#define live_pfGmBlueSpiral 0x0480
#define live_pfGmClimbingWall 0x0481
#define live_plAIArrivedAtGoalMsg 0x0482
#define live_pfGmVarSync 0x0483
#define live_plNetMsgRemovePublicAge 0x0484
#define live_plNetMsgPublicAgeRemoved 0x0485
#define live_plNetClientCommRemovePublicAgeTask 0x0486
#define live_plCCRMessage 0x0487
#define live_plAvOneShotLinkTask 0x0488
#define live_plNetAuthDatabase 0x0489
#define live_plAvatarOpacityCallbackMsg 0x048A
#define live_plAGDetachCallbackMsg 0x048B
#define live_pfMovieEventMsg 0x048C
#define live_plMovieMsg 0x048D
#define live_plPipeTexMakeMsg 0x048E
#define live_plEventLog 0x048F
#define live_plDbEventLog 0x0490
#define live_plSyslogEventLog 0x0491
#define live_plCaptureRenderMsg 0x0492
#define live_plAgeLoaded2Msg 0x0493
#define live_plPseudoLinkEffectMsg 0x0494
#define live_plPseudoLinkAnimTriggerMsg 0x0495
#define live_plPseudoLinkAnimCallbackMsg 0x0496
#define live___UNUSED__pfClimbingWallMsg 0x0497
#define live_plClimbEventMsg 0x0498
#define live___UNUSED__plAvBrainQuab 0x0499
#define live_plAccountUpdateMsg 0x049A
#define live_plLinearVelocityMsg 0x049B
#define live_plAngularVelocityMsg 0x049C
#define live_plRideAnimatedPhysMsg 0x049D
#define live_plAvBrainRideAnimatedPhysical 0x049E

#endif
