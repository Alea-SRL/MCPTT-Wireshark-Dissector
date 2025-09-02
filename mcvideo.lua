----------------------------------------
-- script-name: mcvideo.lua
--
-- author: Iñigo García (inigo.garcia@nemergent-solutions.com)

--   MCVIDEO Wireshark Dissector
--   Copyright (C) 2018  Nemergent Initiative http://www.nemergent.com

--   This program is free software: you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation, either version 3 of the License, or
--   (at your option) any later version.

--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.

--   You should have received a copy of the GNU General Public License
--   along with this program.  If not, see <http://www.gnu.org/licenses/>.

--
-- Beta version 0.1
--
--
-- OVERVIEW:
-- This script provides a dissector for the Mission Critical VIDEO (MCVIDEO) defined by the 3GPP in the TS 24.581.

dofile(persconffile_path('plugins') .. "/mc-common.lua")

-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
local DEBUG = debug_level.LEVEL_1

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if DEBUG > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"MCVIDEO: ", ...}," "))
        end

        if DEBUG > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint("Nemergent MCVIDEO Wireshark dissector (Nemergent Initiative http://www.nemergent.com)")
dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

-- creates a Proto object, but doesn't register it yet
local mcvideo_0 = Proto("mcvideo_0", "Mission Critical Video Protocol Transmission Control (0 type)")
local mcvideo_1 = Proto("mcvideo_1", "Mission Critical Video Protocol Transmission Control (1 type)")
local mcvideo_2 = Proto("mcvideo_2", "Mission Critical Video Protocol Transmission Control (2 type)")
local mcvideo_3 = Proto("mcvideo_3", "Mission Critical Video MBMS subchannel Control Protocol")

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.2.3.1-1: Transmission control specific data fields
local field_codes = {
    [0] = "Transmission Priority",
    [1] = "Duration",
    [2] = "Reject Cause",
    [3] = "Queue Info",
    [4] = "User Id of the Transmitting User",
    [5] = "Permission to Request the Transmission",
    [6] = "User ID",
    [7] = "Queue Size",
    [8] = "Message Sequence-Number",
    [9] = "Queued User ID",
    [10] = "Source",
    [11] = "Track Info",
    [12] = "Message Type",
    [13] = "Transmission Indicator",	
	[14] = "Audio SSRC of the Transmitting User",
	[15] = "Result",
	[16] = "Message Name",
	[17] = "Overriding ID",
	[18] = "Overridden ID",
	[19] = "Reception Priority",
	[20] = "MCVideo Group Identity",
	[21] = "Functional Alias field ID",
	[22] = "Reception Mode",
	[24] = "Video SSRC of the Transmitting User"
}

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.2.2.1-1: Transmission control specific messages sent by the transmission participant
local type_codes_0 = {
    [0] = "Transmission Request",
    [2] = "Transmission Release",
    [3] = "Queue Position Request",
    [4] = "Receive Media Request",
    [5] = "Transmission Cancel Request",  -- mantained for retrocompatibility
    [7] = "Remote Transmission request",
    [8] = "Remote Transmission cancel request"
}

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.2.2.1-2: Transmission control specific messages sent by the transmission control server
local type_codes_1 = {
    [0] = "Transmission Granted",
    [1] = "Transmission Rejected",
    [2] = "Transmission Arbitration Taken",
    [3] = "Transmission Arbitration Release",
    [4] = "Transmission Revoked",
    [5] = "Queue Position Info",
    [6] = "Media transmission notification",
	[7] = "Receive media response",
	[8] = "Media reception notification",
	[9] = "Transmission cancel response",  -- mantained for retrocompatibility
	[10] = "Transmission cancel request notify",
	[11] = "Remote Transmission response",
	[12] = "Remote Transmission cancel response",
	[13] = "Media reception override notification",
	[14] = "Transmission end notify",
	[15] = "Transmission idle"
}

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.2.2.1-3: Transmission control specific messages sent by both the transmission control server and transmission control participant
local type_codes_2 = {
    [0] = "Transmission end request",
    [1] = "Transmission end response",
    [2] = "Media reception end request",
    [3] = "Media reception end response",
    [4] = "Transmission control ack"
}

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.3.2-1: MBMS subchannel control protocol messages
local type_codes_3 = {
    [0] = "Map Group To Bearer",
    [1] = "Unmap Group To Bearer",
    [2] = "Application Paging"
    -- Bearer Announcement, Subtype "a" ???
}

-- 3GPP TS 24.581 version 18.5.0
-- Table 9.3.3.1-1: MBMS subchannel control specific data fields
local field_codes_3 = {
    [0] = "MBMS Subchannel ",
    [1] = "TMGI",
    [2] = "MCVideo Group ID"
    -- Monitoring state , Subtype "b" ???
}

local ip_version = {
    [0] = "IP version 4",
    [1] = "IP version 6"
}

local ack_code = {
    [0] = "ACK not required",
    [1] = "ACK Required",
}

-- 3GPP TS 24.380 version 18.6.0
-- Table 8.2.3.12-1: Source field coding
local source_code = {
    [0] = "Transmission Participant",
    [1] = "Participating MCPTT Function",
    [2] = "Controlling MCPTT Function",
    [3] = "Non-Controlling MCPTT Function"
}

-- 3GPP TS 24.581 version 18.5.0
-- 9.2.6.2	Rejection cause codes and rejection cause phrase
local reject_cause = {
    [1] = "Transmission limit reached",
    [2] = "Internal transmission control server error",
    [3] = "Only one participant",
    [4] = "Retry-after timer has not expired",
    [5] = "Receive only",
    [6] = "No resources available",
    [255] = "Other reason"
}

-- 3GPP TS 24.581 version 18.5.0
-- 9.2.10.2	Revoke cause codes and revoke cause phrase
local revoke_cause = {
    [1] = "Only one MCVideo client",
    [2] = "Media burst too long",
    [3] = "No permission to send a Media Burst",
    [4] = "Media Burst pre-empted",
    [5] = "Terminate the RTP stream",
    [6] = "No resources available",
    [7] = "Queue the transmission",
    [8] = "No receiving participant",
    [255] = "Other reason"
}

-- MCVIDEO_0
local pf_type_0			= ProtoField.new ("Message type", "mcvideo_0.type", ftypes.UINT8, type_codes_0, base.DEC, 0x0F)
local pf_ackreq_0       = ProtoField.new ("ACK Requirement", "mcvideo_0.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_0		= ProtoField.uint16 ("mcvideo_0.txprio", "Transmission Priority", base.DEC)
local pf_duration_0     = ProtoField.uint16 ("mcvideo_0.duration", "Duration (s)", base.DEC)
local pf_reject_cause_0 = ProtoField.new ("Reject Cause", "mcvideo_0.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_revoke_cause_0 = ProtoField.new ("Revoke Cause", "mcvideo_0.revcause", ftypes.UINT16, revoke_cause, base.DEC)
local pf_reject_phrase_0= ProtoField.new ("Reject Phrase", "mcvideo_0.rejphrase", ftypes.STRING)
local pf_queue_info_0   = ProtoField.uint16 ("mcvideo_0.queue", "Queue place", base.DEC)
local pf_queue_unknown_0= ProtoField.new ("Queue place not kwnown", "mcvideo_0.queue_unknown", ftypes.STRING)
local pf_queue_prio_0   = ProtoField.uint16 ("mcvideo_0.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_0   = ProtoField.new ("Granted Party's Identity", "mcvideo_0.grantedid", ftypes.STRING)
local pf_req_perm_0     = ProtoField.bool ("mcvideo_0.reqperm", "Permission to Request the Transmission")
local pf_user_id_0      = ProtoField.new ("User ID", "mcvideo_0.userid", ftypes.STRING)
local pf_queue_size_0   = ProtoField.uint16 ("mcvideo_0.queuesize", "Queue Size", base.DEC)
local pf_sequence_0     = ProtoField.uint16 ("mcvideo_0.sequence", "Sequence Number", base.DEC)
local pf_queued_id_0    = ProtoField.new ("Queued User ID", "mcvideo_0.queuedid", ftypes.STRING)
local pf_source_0       = ProtoField.new ("Source", "mcvideo_0.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_0       = ProtoField.new ("Message ACK type", "mcvideo_0.acktype", ftypes.UINT16, type_codes_0, base.DEC, 0x0700)
local pf_indicators_0     = ProtoField.new ("Transmission Indicator", "mcvideo_0.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_0     = ProtoField.new ("Normal", "mcvideo_0.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_0      = ProtoField.new ("Broadcast Group", "mcvideo_0.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_0        = ProtoField.new ("System", "mcvideo_0.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_0      = ProtoField.new ("Emergency", "mcvideo_0.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_0      = ProtoField.new ("Imminent Peril", "mcvideo_0.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_audio_ssrc_0	  = ProtoField.uint32 ("mcvideo_0.audio_ssrc", "Audio SSRC", base.DEC)
local pf_video_ssrc_0	  = ProtoField.uint32 ("mcvideo_0.video_ssrc", "Video SSRC", base.DEC)
local pf_result_0		  = ProtoField.bool ("mcvideo_0.result", "Result")
local pf_msg_name_0		  = ProtoField.new ("Message name", "mcvideo_0.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_0		     = ProtoField.uint16 ("mcvideo_0.rxprio", "Reception Priority", base.DEC)
local pf_functional_alias_0  = ProtoField.new ("Functional Alias", "mcvideo_0.functional_alias", ftypes.STRING)

local pf_trackinfo_0      = ProtoField.new ("Track Info", "mcvideo_0.trackinfo", ftypes.NONE)
local pf_ti_queueing_0    = ProtoField.new ("Queueing capability", "mcvideo_0.queueingcapability", ftypes.BOOLEAN)
local pf_ti_parttypelen_0 = ProtoField.new ("Participant type length", "mcvideo_0.participanttypelen", ftypes.UINT8)
local pf_ti_parttype_0    = ProtoField.new ("Participant type", "mcvideo_0.participanttype", ftypes.STRING)
local pf_ti_partref_0     = ProtoField.new ("Participant ref", "mcvideo_0.participantref", ftypes.UINT32)

-- MCVIDEO_1
local pf_type_1			= ProtoField.new ("Message type", "mcvideo_1.type", ftypes.UINT8, type_codes_1, base.DEC, 0x0F)
local pf_ackreq_1        = ProtoField.new ("ACK Requirement", "mcvideo_1.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_1			= ProtoField.uint16 ("mcvideo_1.txprio", "Transmission Priority", base.DEC)
local pf_duration_1       = ProtoField.uint16 ("mcvideo_1.duration", "Duration (s)", base.DEC)
local pf_reject_cause_1   = ProtoField.new ("Reject Cause", "mcvideo_1.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_revoke_cause_1   = ProtoField.new ("Revoke Cause", "mcvideo_1.revcause", ftypes.UINT16, revoke_cause, base.DEC)
local pf_reject_phrase_1  = ProtoField.new ("Reject Phrase", "mcvideo_1.rejphrase", ftypes.STRING)
local pf_queue_info_1     = ProtoField.uint16 ("mcvideo_1.queue", "Queue place", base.DEC)
local pf_queue_unknown_1  = ProtoField.new ("Queue place not kwnown", "mcvideo_1.queue_unknown", ftypes.STRING)
local pf_queue_prio_1     = ProtoField.uint16 ("mcvideo_1.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_1     = ProtoField.new ("Granted Party's Identity", "mcvideo_1.grantedid", ftypes.STRING)
local pf_req_perm_1       = ProtoField.bool ("mcvideo_1.reqperm", "Permission to Request the Transmission")
local pf_user_id_1        = ProtoField.new ("User ID", "mcvideo_1.userid", ftypes.STRING)
local pf_queue_size_1     = ProtoField.uint16 ("mcvideo_1.queuesize", "Queue Size", base.DEC)
local pf_sequence_1       = ProtoField.uint16 ("mcvideo_1.sequence", "Sequence Number", base.DEC)
local pf_queued_id_1      = ProtoField.new ("Queued User ID", "mcvideo_1.queuedid", ftypes.STRING)
local pf_source_1         = ProtoField.new ("Source", "mcvideo_1.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_1       = ProtoField.new ("Message ACK type", "mcvideo_1.acktype", ftypes.UINT16, type_codes_1, base.DEC, 0x0700)
local pf_indicators_1     = ProtoField.new ("Transmission Indicator", "mcvideo_1.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_1     = ProtoField.new ("Normal", "mcvideo_1.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_1      = ProtoField.new ("Broadcast Group", "mcvideo_1.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_1        = ProtoField.new ("System", "mcvideo_1.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_1      = ProtoField.new ("Emergency", "mcvideo_1.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_1      = ProtoField.new ("Imminent Peril", "mcvideo_1.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_audio_ssrc_1	  = ProtoField.uint32 ("mcvideo_1.audio_ssrc", "Audio SSRC", base.DEC)
local pf_video_ssrc_1	  = ProtoField.uint32 ("mcvideo_1.video_ssrc", "Video SSRC", base.DEC)
local pf_result_1		  = ProtoField.bool ("mcvideo_1.result", "Result")
local pf_msg_name_1		  = ProtoField.new ("Message name", "mcvideo_1.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_1		     = ProtoField.uint16 ("mcvideo_1.rxprio", "Reception Priority", base.DEC)
local pf_functional_alias_1  = ProtoField.new ("Functional Alias", "mcvideo_1.functional_alias", ftypes.STRING)

-- MCVIDEO_2
local pf_trackinfo_1      = ProtoField.new ("Track Info", "mcvideo_1.trackinfo", ftypes.NONE)
local pf_ti_queueing_1    = ProtoField.new ("Queueing capability", "mcvideo_1.queueingcapability", ftypes.BOOLEAN)
local pf_ti_parttypelen_1 = ProtoField.new ("Participant type length", "mcvideo_1.participanttypelen", ftypes.UINT8)
local pf_ti_parttype_1    = ProtoField.new ("Participant type", "mcvideo_1.participanttype", ftypes.STRING)
local pf_ti_partref_1     = ProtoField.new ("Participant ref", "mcvideo_1.participantref", ftypes.UINT32)

local pf_type_2			= ProtoField.new ("Message type", "mcvideo_2.type", ftypes.UINT8, type_codes_2, base.DEC, 0x0F)
local pf_ackreq_2         = ProtoField.new ("ACK Requirement", "mcvideo_2.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_2			= ProtoField.uint16 ("mcvideo_2.txprio", "Transmission Priority", base.DEC)
local pf_duration_2       = ProtoField.uint16 ("mcvideo_2.duration", "Duration (s)", base.DEC)
local pf_reject_cause_2   = ProtoField.new ("Reject Cause", "mcvideo_2.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_revoke_cause_2   = ProtoField.new ("Revoke Cause", "mcvideo_2.revcause", ftypes.UINT16, revoke_cause, base.DEC)
local pf_reject_phrase_2  = ProtoField.new ("Reject Phrase", "mcvideo_2.rejphrase", ftypes.STRING)
local pf_queue_info_2     = ProtoField.uint16 ("mcvideo_2.queue", "Queue place", base.DEC)
local pf_queue_unknown_2  = ProtoField.new ("Queue place not kwnown", "mcvideo_2.queue_unknown", ftypes.STRING)
local pf_queue_prio_2     = ProtoField.uint16 ("mcvideo_2.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_2     = ProtoField.new ("Granted Party's Identity", "mcvideo_2.grantedid", ftypes.STRING)
local pf_req_perm_2       = ProtoField.bool ("mcvideo_2.reqperm", "Permission to Request the Transmission")
local pf_user_id_2        = ProtoField.new ("User ID", "mcvideo_2.userid", ftypes.STRING)
local pf_queue_size_2     = ProtoField.uint16 ("mcvideo_2.queuesize", "Queue Size", base.DEC)
local pf_sequence_2       = ProtoField.uint16 ("mcvideo_2.sequence", "Sequence Number", base.DEC)
local pf_queued_id_2      = ProtoField.new ("Queued User ID", "mcvideo_2.queuedid", ftypes.STRING)
local pf_source_2         = ProtoField.new ("Source", "mcvideo_2.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_2       = ProtoField.new ("Message ACK type", "mcvideo_2.acktype", ftypes.UINT16, type_codes_2, base.DEC, 0x0700)
local pf_indicators_2     = ProtoField.new ("Transmission Indicator", "mcvideo_2.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_2     = ProtoField.new ("Normal", "mcvideo_2.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_2      = ProtoField.new ("Broadcast Group", "mcvideo_2.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_2        = ProtoField.new ("System", "mcvideo_2.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_2      = ProtoField.new ("Emergency", "mcvideo_2.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_2      = ProtoField.new ("Imminent Peril", "mcvideo_2.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_audio_ssrc_2	  = ProtoField.uint32 ("mcvideo_2.audio_ssrc", "Audio SSRC", base.DEC)
local pf_video_ssrc_2	  = ProtoField.uint32 ("mcvideo_2.video_ssrc", "Video SSRC", base.DEC)
local pf_result_2			= ProtoField.bool ("mcvideo_2.result", "Result")
local pf_msg_name_2		= ProtoField.new ("Message name", "mcvideo_2.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_2		= ProtoField.uint16 ("mcvideo_2.rxprio", "Reception Priority", base.DEC)

local pf_trackinfo_2      = ProtoField.new ("Track Info", "mcvideo_2.trackinfo", ftypes.NONE)
local pf_ti_queueing_2    = ProtoField.new ("Queueing capability", "mcvideo_2.queueingcapability", ftypes.BOOLEAN)
local pf_ti_parttypelen_2 = ProtoField.new ("Participant type length", "mcvideo_2.participanttypelen", ftypes.UINT8)
local pf_ti_parttype_2    = ProtoField.new ("Participant type", "mcvideo_2.participanttype", ftypes.STRING)
local pf_ti_partref_2     = ProtoField.new ("Participant ref", "mcvideo_2.participantref", ftypes.UINT32)

-- MCVIDEO_3

local pf_type_3                 = ProtoField.new ("Message type", "mcvideo_3.type", ftypes.UINT8, type_codes_3, base.DEC, 0x0F)
local pf_group_id_3             = ProtoField.new ("MCVideo Group Identity", "mcvideo_3.group_id", ftypes.STRING)
local pf_tmgi                   = ProtoField.new ("Temporary Mobile Group Identity (TMGI)", "mcvideo_3.tmgi", ftypes.BYTES)
local pf_subchannel             = ProtoField.new ("MBMS Subchannel", "mcvideo_3.mbms_subchannel", ftypes.BYTES)
local pf_video_m_line           = ProtoField.new ("Video m-line Number", "mcvideo_3.video_m_line", ftypes.UINT8, nil, base.DEC, 0xF0)
local pf_audio_m_line           = ProtoField.new ("Audio m-line Number", "mcvideo_3.audio_m_line", ftypes.UINT8, nil, base.DEC, 0x0F)
local pf_control_m_line         = ProtoField.new ("Control m-line Number", "mcvideo_3.control_m_line", ftypes.UINT8, nil, base.DEC, 0xF0)
local pf_fec_m_line             = ProtoField.new ("FEC m-line Number", "mcvideo_3.fec_m_line", ftypes.UINT8, nil, base.DEC, 0x0F)
local pf_ip_version             = ProtoField.new ("IP Version", "mcvideo_3.ip_version", ftypes.UINT8, ip_version, base.DEC, 0xF0)
local pf_transmission_ctrl_port = ProtoField.new ("Transmission Control Port", "mcvideo_3.transmission_ctrl_port", ftypes.UINT32)
local pf_video_media_port       = ProtoField.new ("Video media Port", "mcvideo_3.video_media_port", ftypes.UINT32)
local pf_audio_media_port       = ProtoField.new ("Audio media Port", "mcvideo_3.audio_media_port", ftypes.UINT32)
local pf_fec_port               = ProtoField.new ("FEC Port", "mcvideo_3.fec_port", ftypes.UINT32)
local pf_ipv4_addr              = ProtoField.new ("IPv4 Address", "mcvideo_3.ipv4_address", ftypes.IPv4)
local pf_ipv6_addr              = ProtoField.new ("IPv6 Address", "mcvideo_3.ipv6_address", ftypes.IPv6)

local pf_debug          = ProtoField.uint16 ("mcptt.debug", "Debug", base.DEC)

	


mcvideo_0.fields = {
	pf_ackreq_0,
	pf_type_0,
	pf_txprio_0,
	pf_duration_0,
	pf_reject_cause_0,
	pf_revoke_cause_0,
	pf_reject_phrase_0,
	pf_queue_info_0,
	pf_queue_unknown_0,
	pf_queue_prio_0,
	pf_granted_id_0,
	pf_req_perm_0,
	pf_user_id_0,
	pf_queue_size_0,
	pf_sequence_0,
	pf_queued_id_0,
	pf_source_0,
	pf_msg_type_0,
	pf_indicators_0,
	pf_ind_normal_0,
	pf_ind_broad_0,
	pf_ind_sys_0,
	pf_ind_emerg_0,
	pf_ind_immin_0,
	pf_audio_ssrc_0,
	pf_video_ssrc_0,
    pf_trackinfo_0,
    pf_ti_queueing_0,
    pf_ti_parttypelen_0,
    pf_ti_parttype_0,
    pf_ti_partref_0,
	pf_result_0,
	pf_msg_name_0,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_0,
	pf_functional_alias_0
}


mcvideo_1.fields = {
	pf_ackreq_1,
	pf_type_1,
	pf_txprio_1,
	pf_duration_1,
	pf_reject_cause_1,
	pf_revoke_cause_1,
	pf_reject_phrase_1,
	pf_queue_info_1,
	pf_queue_unknown_1,
	pf_queue_prio_1,
	pf_granted_id_1,
	pf_req_perm_1,
	pf_user_id_1,
	pf_queue_size_1,
	pf_sequence_1,
	pf_queued_id_1,
	pf_source_1,
	pf_msg_type_1,
	pf_indicators_1,
	pf_ind_normal_1,
	pf_ind_broad_1,
	pf_ind_sys_1,
	pf_ind_emerg_1,
	pf_ind_immin_1,
	pf_audio_ssrc_1,
	pf_video_ssrc_1,
    pf_trackinfo_1,
    pf_ti_queueing_1,
    pf_ti_parttypelen_1,
    pf_ti_parttype_1,
    pf_ti_partref_1,
	pf_result_1,
	pf_msg_name_1,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_1,
	pf_functional_alias_1
}

mcvideo_2.fields = {
	pf_ackreq_2,
	pf_type_2,
	pf_txprio_2,
	pf_duration_2,
	pf_reject_cause_2,
	pf_revoke_cause_2,
	pf_reject_phrase_2,
	pf_queue_info_2,
	pf_queue_unknown_2,
	pf_queue_prio_2,
	pf_granted_id_2,
	pf_req_perm_2,
	pf_user_id_2,
	pf_queue_size_2,
	pf_sequence_2,
	pf_queued_id_2,
	pf_source_2,
	pf_msg_type_2,
	pf_indicators_2,
	pf_ind_normal_2,
	pf_ind_broad_2,
	pf_ind_sys_2,
	pf_ind_emerg_2,
	pf_ind_immin_2,
	pf_audio_ssrc_2,
	pf_video_ssrc_2,
    pf_trackinfo_2,
    pf_ti_queueing_2,
    pf_ti_parttypelen_2,
    pf_ti_parttype_2,
    pf_ti_partref_2,
	pf_result_2,
	pf_msg_name_2,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_2
}

mcvideo_3.fields = {
    pf_type_3,
    pf_group_id_3,
    pf_tmgi,
    pf_subchannel,
    pf_video_m_line,
    pf_audio_m_line,
    pf_control_m_line,
    pf_fec_m_line,
    pf_ip_version,
    pf_transmission_ctrl_port,
    pf_video_media_port,
    pf_audio_media_port,
    pf_fec_port,
    pf_ipv4_addr,
    pf_ipv6_addr
}

-- Local values for our use
local type_0    = Field.new("mcvideo_0.type")
local type_1    = Field.new("mcvideo_1.type")
local type_2    = Field.new("mcvideo_2.type")
local type_3    = Field.new("mcvideo_3.type")


 local grantedid_mcvideo_0 = Field.new("mcvideo_0.grantedid")
 local duration_mcvideo_0  = Field.new("mcvideo_0.duration")
 local rejphrase_mcvideo_0 = Field.new("mcvideo_0.rejphrase")

 local grantedid_mcvideo_1 = Field.new("mcvideo_1.grantedid")
 local duration_mcvideo_1  = Field.new("mcvideo_1.duration")
 local rejphrase_mcvideo_1 = Field.new("mcvideo_1.rejphrase")

 local grantedid_mcvideo_2 = Field.new("mcvideo_2.grantedid")
 local duration_mcvideo_2  = Field.new("mcvideo_2.duration")
 local rejphrase_mcvideo_2 = Field.new("mcvideo_2.rejphrase")

function mcvideo_0.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_0.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV0")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_0, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_0, tvbuf:range(0,1))
    tree:add(pf_type_0, tvbuf:range(0,1))

    local pk_info = "MCV0 " .. type_codes_0[type_0().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        local pad_calc = rtcp_padding(pos, tvbuf, pktlen, pktlen_remaining)
        if pad_calc == -1 then
            return
        elseif pad_calc == -2 then
            tree:add_proto_expert_info(ef_bad_field)
            return
        elseif pad_calc ~= nil and pad_calc > 0 then
            pos = pad_calc
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Transmission Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_txprio_0, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_0().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_0().value == 4 then
                tree:add(pf_revoke_cause_0, tvbuf:range(pos,2))
            elseif type_0().value == 1 then
                tree:add(pf_reject_cause_0, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                local field_start = pos
                tree:add(pf_reject_phrase_0, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_0().display ..")"
                pktinfo.cols.info = pk_info

                -- Consume the possible padding
                pos = pos + field_padding(pos, field_start, 0)
            end

        elseif field_name == "Queue Info" then --TODO: Not Tested
            dprint2("============Queue Info")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.5-1: Queue Info field coding
            -- Add the Queue Info to the tree
            local queue_pos = tvbuf:range(pos,1):uint()
            if queue_pos == 65535 then
                tree:add(pf_queue_unknown_0, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_0, "Client not queued")
            else
                tree:add(pf_queue_info_0, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_0, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "User Id of the Transmitting User" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            local field_start = pos
            tree:add(pf_granted_id_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_0().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            local field_start = pos
            tree:add(pf_queued_id_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Message Sequence-Number" then --TODO: Not Tested
            dprint2("============Message Sequence-Number")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_sequence_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_0, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            local field_start = pos
            tree:add(pf_user_id_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)
		
		elseif field_name == "Audio SSRC of the Transmitting User" then
			dprint2("============Audio SSRC of the Transmitting User")
			-- Get the field length (8 bits) (it should be always 6)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Audio SSRC to the tree (only 32 bits, the other 16 are spare)
			tree:add(pf_audio_ssrc_0, tvbuf:range(pos,4))
            pos = pos + field_len

        elseif field_name == "Video SSRC of the Transmitting User" then
            dprint2("============Video SSRC of the Transmitting User")
            -- Get the field length (8 bits) (it should be always 6)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Video SSRC to the tree (only 32 bits, the other 16 are spare)
            tree:add(pf_video_ssrc_0, tvbuf:range(pos,4))
            pos = pos + field_len
		
        elseif field_name == "Track Info" then
            dprint2("============Track Info");
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):uint()
            pos = pos + 1
            local field_start = pos

            -- Create a new subtree for Track Info
            local track_info_tree = tree:add(pf_trackinfo_0, tvbuf:range(pos, field_len))
            
            -- Add the queueing capability
            track_info_tree:add(pf_ti_queueing_0, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Get the participant type length (8 bits)
            local parttype_len = tvbuf:range(pos, 1):uint()
            -- Add the participant type length
            track_info_tree:add(pf_ti_parttypelen_0, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Add the participant type
            track_info_tree:add(pf_ti_parttype_0, tvbuf:range(pos, parttype_len))
            pos = pos + parttype_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, pos - parttype_len, 0)

            while(pos < field_start + field_len)
            do
                track_info_tree:add(pf_ti_partref_0, tvbuf:range(pos, 4))
                pos = pos + 4
            end
        
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_0, tvbuf:range(pos,field_len))
            pos = pos + field_len
		
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_0, tvbuf:range(pos,4))
            pos = pos + field_len
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_0, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Functional Alias field ID" then
            dprint2("============Functional Alias field ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Functional Alias to the tree
            local field_start = pos
            tree:add(pf_functional_alias_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

		end
        pktlen_remaining = pktlen - pos
    end


    dprint2("mcvideo_0.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcvideo_1.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_1.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV1")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_1, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_1, tvbuf:range(0,1))
    tree:add(pf_type_1, tvbuf:range(0,1))

    local pk_info = "MCV1 " .. type_codes_1[type_1().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        local pad_calc = rtcp_padding(pos, tvbuf, pktlen, pktlen_remaining)
        if pad_calc == -1 then
            return
        elseif pad_calc == -2 then
            tree:add_proto_expert_info(ef_bad_field)
            return
        elseif pad_calc ~= nil and pad_calc > 0 then
            pos = pad_calc
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Floor Priority field coding
            -- Add the Floor priority to the tree
            tree:add(pf_txprio_1, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_1().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_1().value == 4 then
                tree:add(pf_revoke_cause_1, tvbuf:range(pos,2))
            elseif type_1().value == 1 then
                tree:add(pf_reject_cause_1, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                local field_start = pos
                tree:add(pf_reject_phrase_1, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_1().display ..")"
                pktinfo.cols.info = pk_info

                -- Consume the possible padding
                pos = pos + field_padding(pos, field_start, 0)
            end

        elseif field_name == "Queue Info" then --TODO: Not Tested
            dprint2("============Queue Info")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.5-1: Queue Info field coding
            -- Add the Queue Info to the tree
            local queue_pos = tvbuf:range(pos,1):uint()
            if queue_pos == 65535 then
                tree:add(pf_queue_unknown_1, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_1, "Client not queued")
            else
                tree:add(pf_queue_info_1, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_1, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "User Id of the Transmitting User" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            local field_start = pos
            tree:add(pf_granted_id_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_1().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            local field_start = pos
            tree:add(pf_queued_id_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Message Sequence-Number" then --TODO: Not Tested
            dprint2("============Message Sequence-Number")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_sequence_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_1, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            local field_start = pos
            tree:add(pf_user_id_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

		elseif field_name == "Audio SSRC of the Transmitting User" then
            dprint2("============Audio SSRC of the Transmitting User")
            -- Get the field length (8 bits) (it should be always 6)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Audio SSRC to the tree (only 32 bits, the other 16 are spare)
            tree:add(pf_audio_ssrc_1, tvbuf:range(pos,4))
            pos = pos + field_len

        elseif field_name == "Video SSRC of the Transmitting User" then
            dprint2("============Video SSRC of the Transmitting User")
            -- Get the field length (8 bits) (it should be always 6)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Video SSRC to the tree (only 32 bits, the other 16 are spare)
            tree:add(pf_video_ssrc_1, tvbuf:range(pos,4))
            pos = pos + field_len
		
        elseif field_name == "Track Info" then
            dprint2("============Track Info");
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):uint()
            pos = pos + 1
            local field_start = pos

            -- Create a new subtree for Track Info
            local track_info_tree = tree:add(pf_trackinfo_1, tvbuf:range(pos, field_len))
            
            -- Add the queueing capability
            track_info_tree:add(pf_ti_queueing_1, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Get the participant type length (8 bits)
            local parttype_len = tvbuf:range(pos, 1):uint()
            -- Add the participant type length
            track_info_tree:add(pf_ti_parttypelen_1, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Add the participant type
            track_info_tree:add(pf_ti_parttype_1, tvbuf:range(pos, parttype_len))
            pos = pos + parttype_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, pos - parttype_len, 0)

            while(pos < field_start + field_len)
            do
                track_info_tree:add(pf_ti_partref_1, tvbuf:range(pos, 4))
                pos = pos + 4
            end
        
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_1, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_1, tvbuf:range(pos,4))
            pos = pos + field_len
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_1, tvbuf:range(pos,1))

            pos = pos + field_len

		elseif field_name == "Functional Alias field ID" then
            dprint2("============Functional Alias field ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Functional Alias to the tree
            local field_start = pos
            tree:add(pf_functional_alias_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        end
        pktlen_remaining = pktlen - pos

    end


    dprint2("mcvideo_1.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcvideo_2.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_2.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV2")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_2, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_2, tvbuf:range(0,1))
    tree:add(pf_type_2, tvbuf:range(0,1))

    local pk_info = "MCV2 " .. type_codes_2[type_2().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    local last_message_name = "MCV2"

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        if pktlen_remaining < MIN_FIELD_LEN then
            tree:add_proto_expert_info(ef_bad_field)
            return
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Floor Priority field coding
            -- Add the Floor priority to the tree
            tree:add(pf_txprio_2, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_2().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_2().value == 4 then
                tree:add(pf_revoke_cause_2, tvbuf:range(pos,2))
            elseif type_2().value == 1 then
                tree:add(pf_reject_cause_2, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                local field_start = pos
                tree:add(pf_reject_phrase_2, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_2().display ..")"
                pktinfo.cols.info = pk_info

                -- Consume the possible padding
                pos = pos + field_padding(pos, field_start, 0)
            end

        elseif field_name == "Queue Info" then --TODO: Not Tested
            dprint2("============Queue Info")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.5-1: Queue Info field coding
            -- Add the Queue Info to the tree
            local queue_pos = tvbuf:range(pos,1):uint()
            if queue_pos == 65535 then
                tree:add(pf_queue_unknown_2, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_2, "Client not queued")
            else
                tree:add(pf_queue_info_2, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_2, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "User Id of the Transmitting User" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            local field_start = pos
            tree:add(pf_granted_id_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_2().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            local field_start = pos
            tree:add(pf_queued_id_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "Message Sequence-Number" then --TODO: Not Tested
            dprint2("============Message Sequence-Number")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_sequence_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- The ACK Message Type should look at the message name you're acknowledging
            if last_message_name == "MCV0" then
                tree:add(pf_msg_type_0, tvbuf:range(pos,field_len))
            elseif last_message_name == "MCV1" then
                tree:add(pf_msg_type_1, tvbuf:range(pos,field_len))
            else
                tree:add(pf_msg_type_2, tvbuf:range(pos,field_len))
            end
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_2, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            local field_start = pos
            tree:add(pf_user_id_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)
		
		elseif field_name == "Audio SSRC of the Transmitting User" then
            dprint2("============Audio SSRC of the Transmitting User")
            -- Get the field length (8 bits) (it should be always 6)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Audio SSRC to the tree (only 32 bits, the other 16 are spare)
            tree:add(pf_audio_ssrc_2, tvbuf:range(pos,4))
            pos = pos + field_len

        elseif field_name == "Video SSRC of the Transmitting User" then
            dprint2("============Video SSRC of the Transmitting User")
            -- Get the field length (8 bits) (it should be always 6)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Video SSRC to the tree (only 32 bits, the other 16 are spare)
            tree:add(pf_video_ssrc_2, tvbuf:range(pos,4))
            pos = pos + field_len
		
        elseif field_name == "Track Info" then
            dprint2("============Track Info");
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):uint()
            pos = pos + 1
            local field_start = pos

            -- Create a new subtree for Track Info
            local track_info_tree = tree:add(pf_trackinfo_2, tvbuf:range(pos, field_len))
            
            -- Add the queueing capability
            track_info_tree:add(pf_ti_queueing_2, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Get the participant type length (8 bits)
            local parttype_len = tvbuf:range(pos, 1):uint()
            -- Add the participant type length
            track_info_tree:add(pf_ti_parttypelen_2, tvbuf:range(pos, 1))
            pos = pos + 1

            -- Add the participant type
            track_info_tree:add(pf_ti_parttype_2, tvbuf:range(pos, parttype_len))
            pos = pos + parttype_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, pos - parttype_len, 0)

            while(pos < field_start + field_len)
            do
                track_info_tree:add(pf_ti_partref_2, tvbuf:range(pos, 4))
                pos = pos + 4
            end
        
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_2, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos, 1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_2, tvbuf:range(pos, 4))
			last_message_name = tvbuf:range(pos, 4):string()
            pos = pos + field_len

            dprint2("Last Message Name: " .. last_message_name)
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_2, tvbuf:range(pos,1))

            pos = pos + field_len
		end

        pktlen_remaining = pktlen - pos

    end


    dprint2("mcvideo_2.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcvideo_3.dissector(tvbuf, pktinfo, root)
    dprint2("mcvideo_3.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV3")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_3, tvbuf:range(0, pktlen), "Mission Critical MBMS subchannel Control Protocol")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_type_3, tvbuf:range(0, 1))

    dprint2("MESSAGE TYPE:", type_3().value)
    local pk_info = "MCV3 " .. type_codes_3[type_3().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        local pad_calc = rtcp_padding(pos, tvbuf, pktlen, pktlen_remaining)
        if pad_calc == -1 then
            return
        elseif pad_calc == -2 then
            tree:add_proto_expert_info(ef_bad_field)
            return
        elseif pad_calc ~= nil and pad_calc > 0 then
            pos = pad_calc
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos, 1)
        local field_name = field_codes_3[field_id:uint()]
        pos = pos + 1

        dprint2("Field binary id: ", field_id:uint())
        dprint2("FIELD name: ", field_name)
        dprint2("POS: ", pos - 1)

        if field_name == "MCVideo Group ID" then
            dprint2("============MCVideo Group ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):le_uint()
            pos = pos + 1

            -- Add the MCVideo Group Identity to the tree
            local field_start = pos
            tree:add(pf_group_id_3, tvbuf:range(pos, field_len))
            pos = pos + field_len

            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "TMGI" then
            dprint2("============TMGI")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):le_uint()
            pos = pos + 1

            -- Add the TMGI to the tree
            local field_start = pos
            tree:add(pf_tmgi, tvbuf:range(pos, field_len))
            pos = pos + field_len

            dprint2("Padding until: ", pos)
            -- Consume the possible padding
            pos = pos + field_padding(pos, field_start, 2)

        elseif field_name == "MBMS Subchannel" then
            dprint2("============MBMS Subchannel")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos, 1):le_uint()
            pos = pos + 1

            -- Add the MBMS Subchannel to the tree
            -- Create a new subtree for the MBMS Subchannel
            local subch_tree = tree:add(pf_subchannel, tvbuf:range(pos, field_len))

            local video_line = bit.band(tvbuf:range(pos, 1):int(), 0x00F0)
            local audio_line = bit.band(tvbuf:range(pos, 1):int(), 0x000F)
            subch_tree:add(pf_video_m_line, tvbuf:range(pos, 1))
            subch_tree:add(pf_audio_m_line, tvbuf:range(pos, 1))
            pos = pos + 1
            local control_line = bit.band(tvbuf:range(pos, 1):int(), 0x00F0)
            local fec_line = bit.band(tvbuf:range(pos, 1):int(), 0x000F)
            subch_tree:add(pf_control_m_line, tvbuf:range(pos, 1))
            subch_tree:add(pf_fec_m_line, tvbuf:range(pos, 1))
            pos = pos + 1
            subch_tree:add(pf_ip_version, tvbuf:range(pos, 1))
            local loc_ip_version = bit.rshift(tvbuf:range(pos, 1):int(), 4)
            local loc_ip_version_name = ip_version[loc_ip_version]
            pos = pos + 1
            -- Spare
            pos = pos + 3
            if control_line ~= 0 then
                subch_tree:add(pf_transmission_ctrl_port, tvbuf:range(pos, 4))
                pos = pos + 4
            end
            subch_tree:add(pf_video_media_port, tvbuf:range(pos, 4))
            pos = pos + 4
            if audio_line ~= 0 then
                subch_tree:add(pf_audio_media_port, tvbuf:range(pos, 4))
                pos = pos + 4
            end
            if fec_line ~= 0 then
                subch_tree:add(pf_fec_port, tvbuf:range(pos, 4))
                pos = pos + 4
            end
            if loc_ip_version_name == "IP version 4" then
                subch_tree:add(pf_ipv4_addr, tvbuf:range(pos, 4))
                pos = pos + 4
            elseif loc_ip_version_name == "IP version 6" then
                subch_tree:add(pf_ipv6_addr, tvbuf:range(pos, 16))
                pos = pos + 16
            end
        end

        pktlen_remaining = pktlen - pos
    end



    dprint2("mcvideo_3.dissector returning", pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

-- we want to have our protocol dissection invoked for a specific RTCP APP Name,
-- so get the rtcp.app.name dissector table and add our protocol to it
local dissectorTable = DissectorTable.get("rtcp.app.name")

dissectorTable:add("MCV0", mcvideo_0.dissector)
dissectorTable:add("MCV1", mcvideo_1.dissector)
dissectorTable:add("MCV2", mcvideo_2.dissector)
dissectorTable:add("MCV3", mcvideo_3.dissector)