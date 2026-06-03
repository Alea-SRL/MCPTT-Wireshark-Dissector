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
    [12] = "PRIVATE CALL RELEASE ",
    [13] = "PRIVATE CALL RELEASE ACK ",
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
    probe_response
}

local map_announcement_optional_parameters_IEI_to_descriptor = {
    [80] = confirm_mode_indication,
    [81] = probe_response
}

function monp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = monp_protocol.name

    local subtree = tree:add(monp_protocol, buffer(), "MCPTT Off-Network Protocol Data")

    local message_type_number = buffer(0, 1):uint()

    subtree:add(message_type, buffer(0, 1))

    if message_type_number > 0 and message_type_number < 23 then
        if message_type_number == 1 then
            AddStringWithLength(buffer, subtree, group_id, 1)

        elseif message_type_number == 2 then
            subtree:add(call_id, buffer(1, 2))
            subtree:add(call_type, buffer(3, 1))
            subtree:add(refresh_interval, buffer(4, 2))
            subtree:add(call_start_time, buffer(6, 5), CalculateNSTime(buffer(6, 5))):append_text(" (" .. buffer(6, 5):uint64() .. ")")
            subtree:add(last_call_type_change_time, buffer(11, 5), CalculateNSTime(buffer(11, 5))):append_text(" (" .. buffer(11, 5):uint64() .. ")")
            local offset = AddStringWithLength(buffer, subtree, group_id, 16)
            offset = AddStringWithLength(buffer, subtree, sdp, offset)
            offset = AddStringWithLength(buffer, subtree, originating_user_id, offset)
            offset = AddStringWithLength(buffer, subtree, last_user_to_change_call_type, offset)
            AppendOptionalParameters(buffer, subtree, offset, map_announcement_optional_parameters_IEI_to_descriptor)

        elseif message_type_number == 21 then
            -- 1. Create a TvbRange for the inner MCData message
            local mcdata_range = buffer(1, length - 1)
            -- 2. Convert that range into a standalone sub-Tvb object
            local mcdata_sub_tvb = mcdata_range:tvb("MCDATA Payload")
            -- 3. Pass the newly generated Tvb to the mcdata dissector
            Dissector.get("mcdata"):call(mcdata_sub_tvb, pinfo, subtree)
            -- 4. Set the name that will appeard in the "PROTOCOL" column
            pinfo.cols.protocol:set("MONP/MCDATA")
        end
    end
end

DissectorTable.get("udp.port"):add(8809, monp_protocol)

-- porta custom nostra, da rimuovere
DissectorTable.get("udp.port"):add(54545, monp_protocol)

function AppendOptionalParameters(buffer, subtree, offset, map_IEI_to_descriptor)
    while offset < buffer:len() do
        local IEI = buffer(offset, 1):uint()
        offset = offset + 1
        for key in pairs(map_IEI_to_descriptor) do
            if IEI == key then
                subtree:add(map_IEI_to_descriptor[key], IEI)
                break
            end
        end
    end
end