----------------------------------------
-- script-name: monp.lua
--
-- author: ALEA

--   MCPTT Off-Network Protocol Wireshark Dissector
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
-- This script provides a dissector for the MCPTT Off-Network Protocol (MONP) defined by the 3GPP in the TS [].
-- https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html

local d = require('debug')
require("mc-common")

monp_protocol = Proto("MONP",  "MCPTT Off-Network Protocol")

-- 3GPP TS 24.379 version 19.6.0
-- Table 15.2.2-1: Message types
local MONP_message_types = {
    [1] = "GROUP CALL PROBE",
    [2] = "GROUP CALL ANNOUNCEMENT",
    [3] = "GROUP CALL ACCEPT",
    [4] = "GROUP CALL EMERGENCY END",
    [5] = "GROUP CALL IMMINENT PERIL END",
    [6] = "GROUP CALL BROADCAST",
    [7] = "GROUP CALL BROADCAST END",
    [8] = "PRIVATE CALL SETUP REQUEST",
    [9] = "PRIVATE CALL RINGING",
    [10] = "PRIVATE CALL ACCEPT",
    [11] = "PRIVATE CALL REJECT",
    [12] = "PRIVATE CALL RELEASE",
    [13] = "PRIVATE CALL RELEASE ACK",
    [14] = "PRIVATE CALL ACCEPT ACK",
    [15] = "PRIVATE EMERGENCY CALL CANCEL",
    [16] = "PRIVATE EMERGENCY CALL CANCEL ACK",
    [17] = "GROUP EMERGENCY ALERT",
    [18] = "GROUP EMERGENCY ALERT ACK",
    [19] = "GROUP EMERGENCY ALERT CANCEL",
    [20] = "GROUP EMERGENCY ALERT CANCEL ACK",
    [21] = "MCDATA MESSAGE CARRIER",
    [22] = "MCVIDEO MESSAGE CARRIER"
}

-- 3GPP TS 24.281 version 19.5.0
-- Table 17.2.2-1: Message types
local MONP_MCVIDEO_message_types = {
    [129] = "GROUP CALL PROBE",
    [130] = "GROUP CALL ANNOUNCEMENT",
    [131] = "GROUP CALL ACCEPT",
    [132] = "GROUP CALL EMERGENCY END",
    [133] = "GROUP CALL IMMINENT PERIL END",
    [134] = "GROUP CALL BROADCAST",
    [135] = "GROUP CALL BROADCAST END",
    [136] = "PRIVATE CALL SETUP REQUEST",
    [137] = "PRIVATE CALL RINGING",
    [138] = "PRIVATE CALL ACCEPT",
    [139] = "PRIVATE CALL REJECT",
    [140] = "PRIVATE CALL RELEASE",
    [141] = "PRIVATE CALL RELEASE ACK",
    [142] = "PRIVATE CALL ACCEPT ACK",
    [143] = "GROUP EMERGENCY ALERT",
    [144] = "GROUP EMERGENCY ALERT ACK",
    [145] = "GROUP EMERGENCY ALERT CANCEL",
    [146] = "GROUP EMERGENCY ALERT CANCEL ACK",
    [147] = "PRIVATE REMOTE VIDEO PUSH REQUEST",
    [148] = "GROUP REMOTE VIDEO PUSH REQUEST",
    [149] = "VIDEO PUSH TRYING RESPONSE",
    [150] = "NOTIFY VIDEO PUSH"
}

-- 3GPP TS 24.379 version 19.6.0
-- Table 15.2.11-1: Call types
local MONP_call_types = {
    [1] = "BASIC GROUP CALL",
    [2] = "BROADCAST GROUP CALL",
    [3] = "EMERGENCY GROUP CALL",
    [4] = "IMMINENT PERIL GROUP CALL ",
    [5] = "PRIVATE CALL",
    [6] = "EMERGENCY PRIVATE CALL ",
}

-- 3GPP TS 24.379 version 19.6.0
-- Table 15.2.7-1: Call types
local commencement_modes = {
    [0] = "AUTOMATIC COMMENCEMENT MODE",
    [1] = "MANUAL COMMENCEMENT MODE"
}

-- 3GPP TS 24.379 version 19.6.0
-- Table 15.2.8-1: Reason type
-- 3GPP TS 24.281 version 19.5.0
-- Table 17.2.8-1: Reason type
local reasons = {
    [0] = "REJECT",
    [1] = "MEDIA FAILURE",
    [2] = "BUSY",
    [3] = "E2E SECURITY CONTEXT FAILURE",
    [4] = "FAILED ",
}

-- 3GPP TS 24.281 version 19.5.0
-- Table 17.2.17-1: Source ID type
local MCVIDEO_source_id_types = {
    [0] = "USER ID",
    [1] = "GROUP ID"
}

-- 3GPP TS 24.281 version 19.5.0
-- Table 17.2.18-1: Source ID type
local MCVIDEO_push_results_types = {
    [0] = "SUCCESS",
    [1] = "FAILURE"
}

message_type = ProtoField.uint8("monp.messagetype", "Message Type", base.DEC, MONP_message_types)
group_id = ProtoField.string("monp.MCPTT_group_ID", "MCPTT Group ID")
call_id = ProtoField.uint16("monp.call_identifier", "Call ID", base.DEC)
call_type = ProtoField.uint8("monp.call_type", "Call Type", base.DEC, MONP_call_types)
refresh_interval = ProtoField.uint16("monp.refresh_interval", "Refresh Interval", base.DEC)
call_start_time = ProtoField.absolute_time("monp.call_start_time", "Call Start Time", base.LOCAL)
last_call_type_change_time = ProtoField.absolute_time("monp.last_call_type_change_time", "Last Call Type Change Time", base.LOCAL)
sdp = ProtoField.string("monp.SDP", "SDP")
originating_user_id = ProtoField.string("monp.originating_MCPTT_user_ID", "Originating MCPTT User Id")
last_user_to_change_call_type = ProtoField.string("monp.last_user_to_change_call_type", "Last User To Change Call Type")
confirm_mode_indication = ProtoField.uint8("monp.confirm_mode_indication", "Confirm Mode Indication", base.DEC)
probe_response = ProtoField.uint8("monp.probe_response", "Probe Response", base.DEC)
sending_user_id = ProtoField.string("monp.sending_MCPTT_user_ID", "Sending MCPTT User Id")
commencement_mode = ProtoField.uint8("monp.commencement_mode", "Commencement Mode", base.DEC, commencement_modes)
caller_user_id = ProtoField.string("monp.caller_MCPTT_user_ID", "Caller MCPTT User Id")
callee_user_id = ProtoField.string("monp.callee_MCPTT_user_ID", "Callee MCPTT User Id")
user_location = ProtoField.string("monp.user_location", "User Location")
reason = ProtoField.uint8("monp.reason", "Reason", base.DEC, reasons)
organization_name = ProtoField.string("monp.organization_name", "Organization Name")
mcvideo_message_type = ProtoField.uint8("monp.MCVIDEO_messagetype", "MCVIDEO Message Type", base.DEC, MONP_MCVIDEO_message_types)
mcvideo_group_id = ProtoField.string("monp.MCVIDEO_group_ID", "MCVIDEO Group ID")
mcvideo_originating_user_id = ProtoField.string("monp.originating_MCVIDEO_user_ID", "Originating MCVIDEO User Id")
mcvideo_sending_user_id = ProtoField.string("monp.sending_MCVIDEO_user_ID", "Sending MCVIDEO User Id")
mcvideo_caller_user_id = ProtoField.string("monp.caller_MCVIDEO_user_ID", "Caller MCVIDEO User Id")
mcvideo_callee_user_id = ProtoField.string("monp.callee_MCVIDEO_user_ID", "Callee MCVIDEO User Id")
mcvideo_remote_push_requester_id = ProtoField.string("monp.MCVIDEO_remote_push_requester_id", "MCVIDEO Remote Push Requester")
mcvideo_remote_push_originator_id = ProtoField.string("monp.MCVIDEO_remote_push_originator_id", "MCVIDEO Remote Push Call Originator")
mcvideo_remote_push_recipient_user_id = ProtoField.string("monp.MCVIDEO_remote_push_recipient_user_id", "MCVIDEO Remote Push Call Recipient User")
mcvideo_remote_push_recipient_group_id = ProtoField.string("monp.MCVIDEO_remote_push_recipient__group_id", "MCVIDEO Remote Push Call Recipient Group")
mcvideo_source_type = ProtoField.uint8("monp.MCVIDEO_source_type", "Source ID Type", base.DEC, MCVIDEO_source_id_types)
mcvideo_video_information = ProtoField.string("monp.MCVIDEO_video_information", "Video Information")
mcvideo_push_result = ProtoField.uint8("monp.MCVIDEO_push_result", "Request Redsult", base.DEC, MCVIDEO_push_results_types)
mcvideo_push_request_notifier = ProtoField.string("monp.MCVIDEO_push_request_notifier", "MCVIDEO Remote Push Request Notifier")
mcvideo_push_request_notification_recipient = ProtoField.string("monp.MCVIDEO_push_request_notification_recipient", "MCVIDEO Remote Push Request Notification Recipient")

monp_protocol.fields = {
    message_type,
    group_id,
    call_id,
    call_type,
    refresh_interval,
    call_start_time,
    last_call_type_change_time,
    sdp,
    originating_user_id,
    last_user_to_change_call_type,
    confirm_mode_indication,
    probe_response,
    sending_user_id,
    commencement_mode,
    caller_user_id,
    callee_user_id,
    user_location,
    reason,
    organization_name,
    mcvideo_message_type,
    mcvideo_group_id,
    mcvideo_originating_user_id,
    mcvideo_sending_user_id,
    mcvideo_caller_user_id,
    mcvideo_callee_user_id,
    mcvideo_remote_push_requester_id,
    mcvideo_remote_push_originator_id,
    mcvideo_remote_push_recipient_user_id,
    mcvideo_remote_push_recipient_group_id,
    mcvideo_source_type,
    mcvideo_video_information,
    mcvideo_push_result,
    mcvideo_push_request_notifier,
    mcvideo_push_request_notification_recipient
}

function monp_protocol.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = monp_protocol.name

    local subtree = tree:add(monp_protocol, buffer(), "MCPTT Off-Network Protocol Data")

    local message_type = MONP_message_types[buffer(0, 1):uint()]

    subtree:add(message_type, buffer(0, 1))

    if message_type == "GROUP CALL PROBE" then
        AddStringWithLength(buffer, subtree, group_id, 1)

    elseif message_type == "GROUP CALL ANNOUNCEMENT" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(call_type, buffer(3, 1))
        subtree:add(refresh_interval, buffer(4, 2))
        subtree:add(call_start_time, buffer(6, 5), CalculateNSTime(buffer(6, 5))):append_text(" (" .. buffer(6, 5):uint64() .. ")")
        subtree:add(last_call_type_change_time, buffer(11, 5), CalculateNSTime(buffer(11, 5))):append_text(" (" .. buffer(11, 5):uint64() .. ")")
        local offset = AddStringWithLength(buffer, subtree, group_id, 16)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)
        offset = AddStringWithLength(buffer, subtree, originating_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, last_user_to_change_call_type, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 80 then
                subtree:add(confirm_mode_indication, IEI)
            elseif IEI == 81 then
                subtree:add(probe_response, IEI)
            end
        end

    elseif message_type == "GROUP CALL ACCEPT" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(call_type, buffer(3, 1))
        local offset = AddStringWithLength(buffer, subtree, group_id, 4)
        AddStringWithLength(buffer, subtree, sending_user_id, offset)

    elseif message_type == "PRIVATE CALL SETUP REQUEST" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(commencement_mode, buffer(3, 1))
        subtree:add(call_type, buffer(4, 1))
        local offset = AddStringWithLength(buffer, subtree, caller_user_id, 5)
        offset = AddStringWithLength(buffer, subtree, callee_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 120 then
                AddStringWithLength(buffer, subtree, user_location, offset)
            end
        end

    elseif message_type == "PRIVATE CALL RINGING" then
        subtree:add(call_id, buffer(1, 2))
        local offset = AddStringWithLength(buffer, subtree, caller_user_id, 3)
        AddStringWithLength(buffer, subtree, callee_user_id, offset)

    elseif message_type == "PRIVATE CALL ACCEPT" then
        subtree:add(call_id, buffer(1, 2))
        local offset = AddStringWithLength(buffer, subtree, caller_user_id, 3)
        offset = AddStringWithLength(buffer, subtree, callee_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)

    elseif message_type == "PRIVATE CALL REJECT" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(reason, buffer(3, 1))
        offset = AddStringWithLength(buffer, subtree, caller_user_id, 4)
        AddStringWithLength(buffer, subtree, callee_user_id, offset)

    elseif message_type == "PRIVATE CALL RELEASE" or
           message_type == "PRIVATE CALL RELEASE ACK" or
           message_type == "PRIVATE CALL ACCEPT ACK" or
           message_type == "PRIVATE EMERGENCY CALL CANCEL" or
           message_type == "PRIVATE EMERGENCY CALL CANCEL ACK" then
        subtree:add(call_id, buffer(1, 2))
        local offset = AddStringWithLength(buffer, subtree, caller_user_id, 3)
        AddStringWithLength(buffer, subtree, callee_user_id, offset)

    elseif message_type == "GROUP CALL IMMINENT PERIL END" or message_type == "GROUP CALL EMERGENCY END" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(last_call_type_change_time, buffer(3, 5), CalculateNSTime(buffer(3, 5))):append_text(" (" .. buffer(3, 5):uint64() .. ")")
        offset = AddStringWithLength(buffer, subtree, last_user_to_change_call_type, 8)
        offset = AddStringWithLength(buffer, subtree, group_id, offset)
        AddStringWithLength(buffer, subtree, originating_user_id, offset)

    elseif message_type == "GROUP EMERGENCY ALERT" then
        local offset = AddStringWithLength(buffer, subtree, group_id, 1)
        offset = AddStringWithLength(buffer, subtree, originating_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, organization_name, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 120 then
                AddStringWithLength(buffer, subtree, user_location, offset)
            end
        end

    elseif message_type == "GROUP EMERGENCY ALERT ACK" or message_type == "GROUP EMERGENCY ALERT CANCEL" or message_type == "GROUP EMERGENCY ALERT CANCEL ACK" then
        local offset = AddStringWithLength(buffer, subtree, group_id, 1)
        offset = AddStringWithLength(buffer, subtree, originating_user_id, offset)
        AddStringWithLength(buffer, subtree, sending_user_id, offset)

    elseif message_type == "GROUP CALL BROADCAST" then
        subtree:add(call_id, buffer(1, 2))
        subtree:add(call_type, buffer(3, 1))
        local offset = AddStringWithLength(buffer, subtree, originating_user_id, 4)
        offset = AddStringWithLength(buffer, subtree, group_id, offset)
        AddStringWithLength(buffer, subtree, sdp, offset)

    elseif message_type == "GROUP CALL BROADCAST END" then
        subtree:add(call_id, buffer(1, 2))
        local offset = AddStringWithLength(buffer, subtree, group_id, 3)
        AddStringWithLength(buffer, subtree, originating_user_id, offset)

    elseif message_type == "MCVIDEO MESSAGE CARRIER" then
        monp_mcvideo_dissector(buffer, subtree)
        pinfo.cols.protocol:set("MONP/MCVIDEO")

    elseif message_type == "MCDATA MESSAGE CARRIER" then
        -- 1. Create a TvbRange for the inner MCData message
        local mcdata_range = buffer(1, length - 1)
        -- 2. Convert that range into a standalone sub-Tvb object
        local mcdata_sub_tvb = mcdata_range:tvb("MCDATA Payload")
        -- 3. Pass the newly generated Tvb to the mcdata dissector
        Dissector.get("mcdata"):call(mcdata_sub_tvb, pinfo, subtree)
        -- 4. Set the name that will appear in the "PROTOCOL" column
        pinfo.cols.protocol:set("MONP/MCDATA")
    end
end

function monp_mcvideo_dissector(buffer, subtree)
    local length = buffer:len()

    local mcvideo_message_type = MONP_MCVIDEO_message_types[buffer(1, 1):uint()]

    subtree:add(mcvideo_message_type, buffer(1, 1))

    if mcvideo_message_type == "GROUP CALL PROBE" then
            AddStringWithLength(buffer, subtree, mcvideo_group_id, 2)

    elseif mcvideo_message_type == "GROUP CALL ANNOUNCEMENT" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(call_type, buffer(4, 1))
        subtree:add(refresh_interval, buffer(5, 2))
        subtree:add(call_start_time, buffer(7, 5), CalculateNSTime(buffer(7, 5))):append_text(" (" .. buffer(7, 5):uint64() .. ")")
        subtree:add(last_call_type_change_time, buffer(12, 5), CalculateNSTime(buffer(12, 5))):append_text(" (" .. buffer(12, 5):uint64() .. ")")
        local offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, 17)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)
        offset = AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, last_user_to_change_call_type, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 80 then
                subtree:add(confirm_mode_indication, IEI)
            elseif IEI == 81 then
                subtree:add(probe_response, IEI)
            end
        end

    elseif mcvideo_message_type == "GROUP CALL ACCEPT" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(call_type, buffer(4, 1))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, 5)
        AddStringWithLength(buffer, subtree, mcvideo_sending_user_id, offset)

    elseif mcvideo_message_type == "PRIVATE CALL SETUP REQUEST" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(commencement_mode, buffer(4, 1))
        subtree:add(call_type, buffer(5, 1))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_caller_user_id, 6)
        offset = AddStringWithLength(buffer, subtree, mcvideo_callee_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 120 then
                AddStringWithLength(buffer, subtree, user_location, offset)
            end
        end

    elseif mcvideo_message_type == "PRIVATE CALL RINGING" then
        subtree:add(call_id, buffer(2, 2))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_caller_user_id, 4)
        AddStringWithLength(buffer, subtree, mcvideo_callee_user_id, offset)

    elseif mcvideo_message_type == "PRIVATE CALL ACCEPT" then
        subtree:add(call_id, buffer(2, 2))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_caller_user_id, 4)
        offset = AddStringWithLength(buffer, subtree, mcvideo_callee_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, sdp, offset)

    elseif mcvideo_message_type == "PRIVATE CALL REJECT" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(reason, buffer(4, 1))
        offset = AddStringWithLength(buffer, subtree, mcvideo_caller_user_id, 5)
        AddStringWithLength(buffer, subtree, mcvideo_callee_user_id, offset)

    elseif mcvideo_message_type == "PRIVATE CALL RELEASE" or
           mcvideo_message_type == "PRIVATE CALL RELEASE ACK" or
           mcvideo_message_type == "PRIVATE CALL ACCEPT ACK" then
        subtree:add(call_id, buffer(2, 2))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_caller_user_id, 4)
        AddStringWithLength(buffer, subtree, mcvideo_callee_user_id, offset)

    elseif mcvideo_message_type == "GROUP CALL IMMINENT PERIL END" or message_type == "GROUP CALL EMERGENCY END" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(last_call_type_change_time, buffer(4, 5), CalculateNSTime(buffer(4, 5))):append_text(" (" .. buffer(4, 5):uint64() .. ")")
        offset = AddStringWithLength(buffer, subtree, last_user_to_change_call_type, 9)
        offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, offset)
        AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, offset)

    elseif mcvideo_message_type == "GROUP EMERGENCY ALERT" then
        local offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, 2)
        offset = AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, offset)
        offset = AddStringWithLength(buffer, subtree, organization_name, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 120 then
                AddStringWithLength(buffer, subtree, user_location, offset)
            end
        end

    elseif mcvideo_message_type == "GROUP EMERGENCY ALERT ACK" or message_type == "GROUP EMERGENCY ALERT CANCEL" or message_type == "GROUP EMERGENCY ALERT CANCEL ACK" then
        local offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, 2)
        offset = AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, offset)
        AddStringWithLength(buffer, subtree, mcvideo_sending_user_id, offset)

    elseif mcvideo_message_type == "GROUP CALL BROADCAST" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(call_type, buffer(4, 1))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, 5)
        offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, offset)
        AddStringWithLength(buffer, subtree, sdp, offset)

    elseif mcvideo_message_type == "GROUP CALL BROADCAST END" then
        subtree:add(call_id, buffer(2, 2))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_group_id, 4)
        AddStringWithLength(buffer, subtree, mcvideo_originating_user_id, offset)

    elseif mcvideo_message_type == "PRIVATE REMOTE VIDEO PUSH REQUEST" or mcvideo_message_type == "GROUP REMOTE VIDEO PUSH REQUEST" then
        subtree:add(call_id, buffer(2, 2))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_remote_push_requester_id, 4)
        offset = AddStringWithLength(buffer, subtree, mcvideo_remote_push_originator_id, offset)
        if mcvideo_message_type == "PRIVATE REMOTE VIDEO PUSH REQUEST" then
            offset = AddStringWithLength(buffer, subtree, mcvideo_remote_push_recipient_user_id, offset)
        else
            offset = AddStringWithLength(buffer, subtree, mcvideo_remote_push_recipient_group_id, offset)
        end
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 121 then
                subtree:add(mcvideo_source_type, buffer(offset, 1))
                offset = offset + 1
                AddStringWithLength(buffer, subtree, mcvideo_video_information, offset)
            end
        end

    elseif mcvideo_message_type == "VIDEO PUSH TRYING RESPONSE" then
        subtree:add(call_id, buffer(2, 2))

    elseif mcvideo_message_type == "NOTIFY VIDEO PUSH" then
        subtree:add(call_id, buffer(2, 2))
        subtree:add(mcvideo_push_result, buffer(4, 1))
        local offset = AddStringWithLength(buffer, subtree, mcvideo_push_request_notifier, 5)
        offset = AddStringWithLength(buffer, subtree, mcvideo_push_request_notification_recipient, offset)
        while offset < length do
            local IEI = buffer(offset, 1):uint()
            offset = offset + 1
            if IEI == 122 then
                AddStringWithLength(buffer, subtree, mcvideo_remote_push_recipient_user_id, offset)
            elseif IEI == 123 then
                AddStringWithLength(buffer, subtree, mcvideo_remote_push_recipient_group_id, offset)
            elseif IEI == 32 then
                subtree:add(reason, buffer(offset, 1))
                offset = offset + 1
            end
        end

    end
end

DissectorTable.get("udp.port"):add(8809, monp_protocol)

-- porta custom nostra, da rimuovere
DissectorTable.get("udp.port"):add(54545, monp_protocol)