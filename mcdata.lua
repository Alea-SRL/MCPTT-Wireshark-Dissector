----------------------------------------
-- script-name: mcdata.lua
--
-- author: ALEA

--   MCDATA Wireshark Dissector
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
-- This script provides a dissector for the Mission Critical DATA (MCDATA) defined by the 3GPP in the TS [].
-- https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html

local d = require('debug')
require("mc-common")

mcdata_protocol = Proto("mcdata",  "mcdata SIP Dissector")

-- 3GPP TS 24.282 version 18.11.0
-- Table 15.2.2-1: Message types
local IEI_codes = {
    [1] = "SDS SIGNALLING PAYLOAD",
    [2] = "FD SIGNALLING PAYLOAD",
    [3] = "DATA PAYLOAD",
    [5] = "SDS NOTIFICATION",
    [6] = "FD NOTIFICATION",
    [7] = "SDS OFF-NETWORK MESSAGE",
    [8] = "SDS OFF-NETWORK NOTIFICATION",
    [9] = "FD NETWORK NOTIFICATION",
    [10] = "COMMUNICATION RELEASE",
    [11] = "DEFERRED LIST ACCESS REQUEST",
    [12] = "DEFERRED LIST ACCESS RESPONSE",
    [13] = "FD HTTP TERMINATION",
    [17] = "GROUP EMERGENCY ALERT",
    [18] = "GROUP EMERGENCY ALERT ACK",
    [19] = "GROUP EMERGENCY ALERT CANCEL",
    [20] = "GROUP EMERGENCY ALERT CANCEL ACK",
    [120] = "Payload"
}

-- 3GPP TS 24.282 version 18.11.0
-- Table 15.2.3-1: SDS disposition request type
local DispositionRequest_codes = {
    [0] = "NONE",
    [1] = "DELIVERY",
    [2] = "READ",
    [3] = "DELIVERY AND READ"
}

-- 3GPP TS 24.282 version 18.11.0
-- Table 15.2.4-1: FD disposition request type
local DispositionRequestFD_codes = {
    [1] = "FILE DOWNLOAD COMPLETED UPDATE"
}

-- 3GPP TS 24.282 version 18.11.0
-- Table 15.2.16-1: Mandatory download
local MandatoryDownload_codes = {
    [1] = "MANDATORY DOWNLOAD"
}

-- 3GPP TS 24.282 version 18.11.0
-- Table 15.2.13-2:  Payload content type
local PayloadContentType_codes = {
    [1] = "TEXT",
    [2] = "BINARY",
    [3] = "HYPERLINKS",
    [4] = "FILEURL",
    [5] = "LOCATION",
    [6] = "ENHANCED STATUS",
    -- 7 = Value allocated for use in interworking
    [8] = "LOCATION ALTITUDE",
    [9] = "LOCATION TIMESTAMP",
    [10] = "CODED TEXT"
}

IEI = ProtoField.int8("mcdata.iei", "IEI", base.DEC, IEI_codes)
DateTime_i = ProtoField.uint64("mcdata.datetime_i", "DateTime", base.DEC)
DateTime = ProtoField.absolute_time("mcdata.datetime", "DateTime", base.LOCAL)
conversation_id = ProtoField.string("mcdata.conversation_id", "Conversation ID")
message_id = ProtoField.string("mcdata.message_id", "Message ID")
DispositionRequest = ProtoField.uint8("mcdata.dispositionrequesttype", "Disposition Request Type", base.DEC, DispositionRequest_codes)
PayloadsCount = ProtoField.uint8("mcdata.payload.count", "Number of payloads", base.DEC)
PayloadsTotalSize = ProtoField.uint16("mcdata.payload.TotalSize", "Length of Payload contents", base.DEC)
PayloadsContentType = ProtoField.uint8("mcdata.payload.contenttype", "Payload content type", base.DEC, PayloadContentType_codes)
PayloadsContentText = ProtoField.string("mcdata.payload.contentstring", "Payload content type string")
PayloadsContentURL = ProtoField.string("mcdata.payload.contenturl", "Payload content type url")
DispositionRequestFD = ProtoField.uint8("mcdata.dispositionrequesttypefd", "Disposition Request Type FD", base.DEC, DispositionRequestFD_codes, 128)
MandatoryDownload = ProtoField.uint8("mcdata.mandatorydownload", "Mandatory Download", base.DEC, MandatoryDownload_codes, 128)
sender_id = ProtoField.string("mcdata.sender_id", "Sender ID")
in_reply_to_message_id = ProtoField.string("mcdata.reply_message_id", "In Reply To Message ID")
application_id = ProtoField.string("mcdata.application_id", "Application ID")
group_id = ProtoField.string("mcdata.group_id", "MCDATA Group ID")
recipient_id = ProtoField.string("mcdata.recipient_id", "Recipient MCDATA ID")
extended_application_id = ProtoField.string("mcdata.extended_application_ID", "Extended Application ID")

mcdata_protocol.fields = {
    IEI,
    DateTime_i,
    DateTime,
    conversation_id,
    message_id,
    DispositionRequest,
    DispositionRequestFD,
    PayloadsCount,
    PayloadsTotalSize,
    PayloadsContentType,
    PayloadsContentText,
    PayloadsContentURL,
    MandatoryDownload,
    sender_id,
    in_reply_to_message_id,
    application_id,
    group_id
}

function mcdata_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then 
		return 
	end
	
	pinfo.cols.protocol = mcdata_protocol.name

	local subtree = tree:add(mcdata_protocol, buffer(), "MCDATA Talkway")

	local IEI_number = buffer(0,1):uint()

	subtree:add(IEI, buffer(0,1))

	if IEI_number > 0 and IEI_number < 12 then
		if IEI_number == 1 then
			subtree:add(DateTime_i, buffer(1,5))
			subtree:add(DateTime, buffer(1,5), CalculateNSTime(buffer(1, 5)))
			subtree:add(conversation_id, FormatUUID(string.upper(tostring(buffer(6, 16)))))
			subtree:add(message_id, FormatUUID(string.upper(tostring(buffer(22, 16)))))
			local disposition_type = bit32.band(buffer(38, 1):uint(), 0x0F)
            -- aggiungo un valore "custom" (il buffer serve a Wireshark per fare l'highlight)
            subtree:add_packet_field(DispositionRequest, buffer(38, 1), disposition_type)

        elseif IEI_number == 2 then
            subtree:add(DateTime_i, buffer(1,5))
            subtree:add(DateTime, buffer(1,5), CalculateNSTime(buffer(1, 5)))
            subtree:add(conversation_id, FormatUUID(string.upper(tostring(buffer(6, 16)))))
            subtree:add(message_id, FormatUUID(string.upper(tostring(buffer(22, 16)))))
            subtree:add_le(DispositionRequestFD, buffer(38,1))
            subtree:add_le(MandatoryDownload, buffer(39,1))

            local PayloadsTotalSize_number = 0
            local IEI_Payload_number =  buffer(40,1):le_uint()

            if IEI_Payload_number == 120 then
                subtree:add(PayloadsTotalSize, buffer(41,2))
                PayloadsTotalSize_number =  buffer(41,2):int()
                local payloadsubtree = subtree:add(mcdata_protocol, buffer(), "Payload")
                local payload_type =  buffer(5,1):le_uint()
                payloadsubtree:add(PayloadsContentType, buffer(5,1))
                if payload_type == 4 then
                    payloadsubtree:add(PayloadsContentURL, buffer(6, PayloadsTotalSize_number))
                end
            end

            local offset = 43 + 5 + PayloadsTotalSize_number-1
            IEI_Payload_number =  buffer(offset, 1):le_uint()

            if IEI_Payload_number == 121 then
                offset = offset + 1
                subtree:add(PayloadsTotalSize, buffer(offset, 2))
                PayloadsTotalSize_number =  buffer(offset, 2):int()
                local metadatasubtree = subtree:add(mcdata_protocol, buffer(), "Metadata")
                metadatasubtree:add(PayloadsContentText, buffer(4,PayloadsTotalSize_number-1))
            end

		elseif IEI_number == 3 then
			subtree:add(PayloadsCount, buffer(1,1))
			subtree:add(IEI, buffer(2,1))
		  
			local IEI_Payload_number =  buffer(2,1):uint()
			local PayloadsCount_number =  buffer(1,1):uint()
			
	  		if IEI_Payload_number == 120 then
				subtree:add(PayloadsTotalSize, buffer(3,2))
				local PayloadsTotalSize_number =  buffer(3,2):int()
			
				for i=1,PayloadsCount_number do
					local payloadsubtree = subtree:add(mcdata_protocol, buffer(), "Payload")
					local payload_type =  buffer(5, 1):uint()
					payloadsubtree:add(PayloadsContentType, buffer(5, 1))
					if payload_type == 1 then
						payloadsubtree:add(PayloadsContentText, buffer(6, PayloadsTotalSize_number - 1))
					end
				end
			end

		elseif IEI_number == 5 then
			subtree:add(DispositionRequest, buffer(1, 1))
			subtree:add(DateTime, buffer(2,5), CalculateNSTime(buffer(2, 5))):append_text(" (" .. buffer(2, 5):uint64() .. ")")
			subtree:add(conversation_id, FormatUUID(string.upper(tostring(buffer(7, 16)))))
			subtree:add(message_id, FormatUUID(string.upper(tostring(buffer(23, 16)))))

        elseif IEI_number == 7 then
            subtree:add(DateTime, buffer(1,5), CalculateNSTime(buffer(1, 5))):append_text(" (" .. buffer(1, 5):uint64() .. ")")
            local num_payloads = buffer(6, 1):uint()
            subtree:add(PayloadsCount, buffer(6, 1))
            subtree:add(conversation_id, FormatUUID(string.upper(tostring(buffer(7, 16)))))
            subtree:add(message_id, FormatUUID(string.upper(tostring(buffer(23, 16)))))
            local offset = AddStringWithLength(buffer, subtree, sender_id, 39)
            while offset < length do
                local IEI = buffer(offset, 1):uint()
                local IEI_upper_bits = bit32.band(IEI, 0xF0) -- extract the first 4 bits of the byte
                offset = offset + 1
                if IEI == 33 then -- IN REPLY TO MESSAGE ID
                    subtree:add(in_reply_to_message_id, buffer(offset, 16))
                    offset = offset + 16
                elseif IEI == 34 then -- APPLICATION ID
                    subtree:add(application_id, buffer(offset, 16))
                    offset = offset + 16
                elseif IEI_upper_bits == 128 then -- SDS DISPOSITION REQUEST TYPE (upper 4 bits = IEI; lower 4 bits = value)
                    local disposition_type = bit32.band(IEI, 0x0F)
                    -- aggiungo un valore "custom" (il buffer serve a Wireshark per fare l'highlight)
                    subtree:add_packet_field(DispositionRequest, buffer(offset - 1, 1), disposition_type)
                elseif IEI == 123 then -- MCDATA GROUP ID
                    offset = AddStringWithLength(buffer, subtree, group_id, offset)
                elseif IEI == 124 then -- RECIPIENT MDATA USER ID
                    offset = AddStringWithLength(buffer, subtree, recipient_id, offset)
                elseif IEI == 120 then -- PAYLOAD
                    for i=1,num_payloads do
                        offset = AddStringWithLength(buffer, subtree, PayloadsContentText, offset)
                    end
                elseif IEI == 125 then -- EXTENDED APPLICATION ID
                    offset = AddStringWithLength(buffer, subtree, extended_application_id, offset)
                end
            end

        elseif IEI_number == 8
            subtree:add(DispositionRequest, buffer(1, 1))
            subtree:add(DateTime, buffer(2,5), CalculateNSTime(buffer(2, 5))):append_text(" (" .. buffer(2, 5):uint64() .. ")")
            subtree:add(conversation_id, FormatUUID(string.upper(tostring(buffer(7, 16)))))
            subtree:add(message_id, FormatUUID(string.upper(tostring(buffer(23, 16)))))
            local offset = AddStringWithLength(buffer, subtree, sender_id, 39)
            while offset < length do
                local IEI = buffer(offset, 1):uint()
                offset = offset + 1
                if IEI == 34 then -- APPLICATION ID
                    subtree:add(application_id, buffer(offset, 16))
                    offset = offset + 16
                elseif IEI == 125 then -- EXTENDED APPLICATION ID
                    offset = AddStringWithLength(buffer, subtree, extended_application_id, offset)
                end
            end

		end
	end
end

DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-signalling", mcdata_protocol.dissector)
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-payload", mcdata_protocol.dissector)

function FormatUUID(uuid)
	local count = 0
	local result = ''
	for i = 1, #uuid do
    		local char= uuid:sub(i,i)
		count = count + 1
		result = result .. char
		if count == 8 or count == 12 or count == 16 or count == 20 then
			result  = result .. '-'
		end
	end
	return result
end
