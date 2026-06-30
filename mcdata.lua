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
local Message_types = {
    -- used to discern the type of unprotected and unauthenticated MCDATA Messages:
    [1] =  "SDS SIGNALLING PAYLOAD",
    [2] =  "FD SIGNALLING PAYLOAD",
    [3] =  "DATA PAYLOAD",
    [5] =  "SDS NOTIFICATION",
    [6] =  "FD NOTIFICATION",
    [7] =  "SDS OFF-NETWORK MESSAGE",
    [8] =  "SDS OFF-NETWORK NOTIFICATION",
    [9] =  "FD NETWORK NOTIFICATION",
    [10] = "COMMUNICATION RELEASE",
    [11] = "DEFERRED LIST ACCESS REQUEST",
    [12] = "DEFERRED LIST ACCESS RESPONSE",
    [13] = "FD HTTP TERMINATION",
    [17] = "GROUP EMERGENCY ALERT",
    [18] = "GROUP EMERGENCY ALERT ACK",
    [19] = "GROUP EMERGENCY ALERT CANCEL",
    [20] = "GROUP EMERGENCY ALERT CANCEL ACK",

    -- used to discern the type of protected and unauthenticated MCDATA Messages:
    [65] = "PROTECTED SDS SIGNALLING PAYLOAD",
    [66] = "PROTECTED FD SIGNALLING PAYLOAD",
    [67] = "PROTECTED DATA PAYLOAD",
    [69] = "PROTECTED SDS NOTIFICATION",
    [70] = "PROTECTED FD NOTIFICATION",
    [71] = "PROTECTED SDS OFF-NETWORK MESSAGE",
    [72] = "PROTECTED SDS OFF-NETWORK NOTIFICATION",
    [73] = "PROTECTED FD NETWORK NOTIFICATION",
    [74] = "PROTECTED COMMUNICATION RELEASE",
    [75] = "PROTECTED DEFERRED LIST ACCESS REQUEST",
    [76] = "PROTECTED DEFERRED LIST ACCESS RESPONSE",
    [77] = "PROTECTED FD HTTP TERMINATION",
    [81] = "PROTECTED GROUP EMERGENCY ALERT",
    [82] = "PROTECTED GROUP EMERGENCY ALERT ACK",
    [83] = "PROTECTED GROUP EMERGENCY ALERT CANCEL",
    [84] = "PROTECTED GROUP EMERGENCY ALERT CANCEL ACK",
}

-- used for IEIs of optional fields inside MCDATA messages:
local IEI_codes = {
    [33]  = "InReplyTo message ID",
    [34]  = "Application ID",
    [81]  = "Sender MCData user ID",
    [82]  = "Deferred FD signalling payload",
    [83]  = "Application metadata container",
    [120] = "Payload",
    [121] = "Metadata",
    [122] = "Security parameters and Payload",
    [123] = "MCData group ID",
    [124] = "Recipient MCData user ID",
    [125] = "Extended application ID",
    [126] = "User location",
    [127] = "Organization name",
    [128] = "SDS disposition request type",
    [144] = "FD disposition request type",
    [160] = "Mandatory download",
    [176] = "Data query type",
    [192] = "Extension Response Type",
    [208] = "Release Response Type"
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
    [1]  = "TEXT",
    [2]  = "BINARY",
    [3]  = "HYPERLINKS",
    [4]  = "FILEURL",
    [5]  = "LOCATION",
    [6]  = "ENHANCED STATUS",
    -- 7 = Value allocated for use in interworking
    [8]  = "LOCATION ALTITUDE",
    [9]  = "LOCATION TIMESTAMP",
    [10] = "CODED TEXT"
}

-- RFC 5116: An Interface and Algorithms for Authenticated Encryption
-- section 6: IANA Considerations
local Algorithms = {
    [1] = "AEAD_AES_128_GCM",
    [2] = "AEAD_AES_256_GCM",
    [3] = "AEAD_AES_128_CCM",
    [4] = "AEAD_AES_256_CCM"
}

MessageType                  = ProtoField.int8("mcdata.security_parameters_and_payload.message_type", "Message Type", base.DEC, Message_types)
DateTime                     = ProtoField.absolute_time("mcdata.datetime", "DateTime", base.LOCAL)
ConversationID               = ProtoField.string("mcdata.conversation_id", "Conversation ID")
MessageID                    = ProtoField.string("mcdata.message_id", "Message ID")
DispositionRequest           = ProtoField.uint8("mcdata.disposition_request_type", "Disposition Request Type", base.DEC, DispositionRequest_codes)
PayloadsCount                = ProtoField.uint8("mcdata.payload.count", "Number of payloads", base.DEC)
DispositionRequestFD         = ProtoField.uint8("mcdata.disposition_request_type_fd", "Disposition Request Type FD", base.DEC, DispositionRequestFD_codes)
MandatoryDownload            = ProtoField.uint8("mcdata.mandatory_download", "Mandatory Download", base.DEC, MandatoryDownload_codes)
SenderID                     = ProtoField.string("mcdata.sender_id", "Sender ID")
InReplyToMessageID           = ProtoField.string("mcdata.in_reply_to_message_id", "In Reply To Message ID")
ApplicationID                = ProtoField.string("mcdata.application_id", "Application ID")
GroupID                      = ProtoField.string("mcdata.group_id", "MCDATA Group ID")
RecipientID                  = ProtoField.string("mcdata.recipient_id", "Recipient MCDATA ID")
ExtendedApplicationID        = ProtoField.string("mcdata.extended_application_ID", "Extended Application ID")
UserLocation                 = ProtoField.string("mcdata.user_location", "User Location")
ApplicationMetadataContainer = ProtoField.string("mcdata.application_metadata_container", "Application Metadata Container")
Metadata                     = ProtoField.string("mcdata.metadata", "Metadata")

PayloadContentText           = ProtoField.string("mcdata.payload.content_text", "Payload content type text")
PayloadContentBinary         = ProtoField.bytes("mcdata.payload.content_binary", "Payload content type binary")
PayloadContentHyperlink      = ProtoField.string("mcdata.payload.content_hyperlink", "Payload content type hyperlink")
PayloadContentFileURL        = ProtoField.string("mcdata.payload.content_file_url", "Payload content type file URL")
PayloadContentLocation       = ProtoField.new("Payload content type location", "mcdata.payload.content_location", ftypes.NONE)
PayloadContentLatitude       = ProtoField.double("mcdata.payload.content_location.latitude", "Latitude", BASE_DEC)
PayloadContentLongitude      = ProtoField.double("mcdata.payload.content_location.longitude", "Longitude", BASE_DEC)
PayloadContentEnhancedStatus = ProtoField.uint64("mcdata.payload.content_enhanced_status", "Payload content type enhanced status", base.DEC)
PayloadContentAltitude       = ProtoField.string("mcdata.payload.content_altitude", "Payload content type location altitude")
PayloadContentTimestamp      = ProtoField.string("mcdata.payload.content_timestamp", "Payload content type location timestamp")
PayloadContentCodedText      = ProtoField.string("mcdata.payload.content_coded_text", "Payload content type coded text")

-- 3GPP TS 33.180 version 19.4.0
-- Table 8.5.4.1-1:  MCData Protected Payload message content
SecurityParametersAndPayload = ProtoField.new("Security Parameters And Payload", "mcdata.security_parameters_and_payload", ftypes.NONE)
-- MessageType
-- DateTime
PayloadID                    = ProtoField.int64("mcdata.security_parameters_and_payload.payload_id", "Payload ID", base.DEC)
PayloadSequenceNumber        = ProtoField.int8("mcdata.security_parameters_and_payload.payload_sequence_number", "Payload Sequence Number", base.DEC)
PayloadAlgorithm             = ProtoField.int8("mcdata.security_parameters_and_payload.payload_algorithm", "Payload Algorithm", base.DEC, Algorithms)
SignallingAlgorithm          = ProtoField.int8("mcdata.security_parameters_and_payload.signalling_algorithm", "Signalling Algorithm", base.DEC)
IV                           = ProtoField.bytes("mcdata.security_parameters_and_payload.iv", "IV")
DPPK_ID                      = ProtoField.int64("mcdata.security_parameters_and_payload.dppk-id", "DPPK-ID", base.DEC)
ProtectedPayloadType         = ProtoField.int8("mcdata.security_parameters_and_payload.protected_payload", "Protected Payload Type", base.DEC, Message_types)
ProtectedPayload             = ProtoField.bytes("mcdata.security_parameters_and_payload.protected_payload", "Protected Payload")
MIKEY_SAKKE_I_MESSAGE        = ProtoField.string("mcdata.security_parameters_and_payload.mikey_sakke_i_message", "MIKEY_SAKKE I-MESSAGE")

mcdata_protocol.fields = {
    MessageType,
    DateTime,
    ConversationID,
    MessageID,
    DispositionRequest,
    DispositionRequestFD,
    PayloadsCount,
    MandatoryDownload,
    SenderID,
    InReplyToMessageID,
    ApplicationID,
    GroupID,
    RecipientID,
    ExtendedApplicationID,
    UserLocation,
    ApplicationMetadataContainer,
    Metadata,
    PayloadContentText,
    PayloadContentBinary,
    PayloadContentHyperlink,
    PayloadContentFileURL,
    PayloadContentLocation,
    PayloadContentLatitude,
    PayloadContentLongitude,
    PayloadContentEnhancedStatus,
    PayloadContentAltitude,
    PayloadContentTimestamp,
    PayloadContentCodedText,
    SecurityParametersAndPayload,
    PayloadID,
    PayloadSequenceNumber,
    PayloadAlgorithm,
    SignallingAlgorithm,
    IV,
    DPPK_ID,
    ProtectedPayloadType,
    ProtectedPayload,
    MIKEY_SAKKE_I_MESSAGE
}

function mcdata_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then
		return
	end

	pinfo.cols.protocol = mcdata_protocol.name

	local subtree = tree:add(mcdata_protocol, buffer(), "MCDATA Talkway")

	local pos = 0

	local msg_type_buf = buffer(pos, 1)
	local msg_type_number = msg_type_buf:uint()
	local msg_type_most_significant_bit = bit.band(msg_type_number, 0x40)
	if msg_type_most_significant_bit == 0 then -- for protected messages, the message type will be added by the function "AppendSecurityParametersAndPayload"
	    subtree:add(MessageType, msg_type_buf)
	end
	pos = pos + 1

	local msg_type_text = ""
	if msg_type_number >= 1 and msg_type_number <= 84 then
        msg_type_text = Message_types[msg_type_number]
    end

    if msg_type_text == "SDS SIGNALLING PAYLOAD" or msg_type_text == "FD SIGNALLING PAYLOAD" then
        local datetime_buf = buffer(pos, 5)
        subtree:add(DateTime, datetime_buf, CalculateNSTime(datetime_buf)):append_text(" (" .. datetime_buf:uint64() .. ")")
        pos = pos + 5

        local conversation_id_buf = buffer(pos, 16)
        subtree:add(ConversationID, conversation_id_buf, FormatUUID(conversation_id_buf:bytes():tohex()))
        pos = pos + 16

        local message_id_buf = buffer(pos, 16)
        subtree:add(MessageID, message_id_buf, FormatUUID(message_id_buf:bytes():tohex()))
        pos = pos + 16

        AppendOptionalIEIs(buffer, subtree, pos, false)

    elseif msg_type_text == "DATA PAYLOAD" then
        local num_payloads_buf = buffer(pos, 1)
        subtree:add(PayloadsCount, num_payloads_buf)
        pos = pos + 1

        AppendOptionalIEIs(buffer, subtree, pos, false)

    elseif msg_type_text == "SDS NOTIFICATION" then
        local dispositionrequest_buf = buffer(pos, 1)
        subtree:add(DispositionRequest, dispositionrequest_buf)
        pos = pos + 1

        local datetime_buf = buffer(pos, 5)
        subtree:add(DateTime, datetime_buf, CalculateNSTime(datetime_buf)):append_text(" (" .. datetime_buf:uint64() .. ")")
        pos = pos + 5

        local conversation_id_buf = buffer(pos, 16)
        subtree:add(ConversationID, conversation_id_buf, FormatUUID(conversation_id_buf:bytes():tohex()))
        pos = pos + 16

        local message_id_buf = buffer(pos, 16)
        subtree:add(MessageID, message_id_buf, FormatUUID(message_id_buf:bytes():tohex()))
        pos = pos + 16

        AppendOptionalIEIs(buffer, subtree, pos, false)

    elseif msg_type_text == "SDS OFF-NETWORK MESSAGE" then
        local datetime_buf = buffer(pos, 5)
        subtree:add(DateTime, datetime_buf, CalculateNSTime(datetime_buf)):append_text(" (" .. datetime_buf:uint64() .. ")")
        pos = pos + 5

        local num_payloads_buf = buffer(pos, 1)
        subtree:add(PayloadsCount, num_payloads_buf)
        pos = pos + 1

        local conversation_id_buf = buffer(pos, 16)
        subtree:add(ConversationID, conversation_id_buf, FormatUUID(conversation_id_buf:bytes():tohex()))
        pos = pos + 16

        local message_id_buf = buffer(pos, 16)
        subtree:add(MessageID, message_id_buf, FormatUUID(message_id_buf:bytes():tohex()))
        pos = pos + 16

        pos = AddStringWithLength(buffer, subtree, SenderID, pos)

        AppendOptionalIEIs(buffer, subtree, pos, true)

    elseif msg_type_text == "SDS OFF-NETWORK NOTIFICATION" then
        local dispositionrequest_buf = buffer(pos, 1)
        subtree:add(DispositionRequest, dispositionrequest_buf)
        pos = pos + 1

        local datetime_buf = buffer(pos, 5)
        subtree:add(DateTime, datetime_buf, CalculateNSTime(datetime_buf)):append_text(" (" .. datetime_buf:uint64() .. ")")
        pos = pos + 5

        local conversation_id_buf = buffer(pos, 16)
        subtree:add(ConversationID, conversation_id_buf, FormatUUID(conversation_id_buf:bytes():tohex()))
        pos = pos + 16

        local message_id_buf = buffer(pos, 16)
        subtree:add(MessageID, message_id_buf, FormatUUID(message_id_buf:bytes():tohex()))
        pos = pos + 16

        AppendOptionalIEIs(buffer, subtree, pos, true)

    elseif msg_type_text == "PROTECTED SDS SIGNALLING PAYLOAD" or
           msg_type_text == "PROTECTED FD SIGNALLING PAYLOAD" or
           msg_type_text == "PROTECTED DATA PAYLOAD" or
           msg_type_text == "PROTECTED SDS NOTIFICATION" or
           msg_type_text == "PROTECTED FD NOTIFICATION" then
        AppendSecurityParametersAndPayload(buffer, subtree, 0, 0, false)

    end
end

function AppendOptionalIEIs(buffer, subtree, pos, off_network)
    local length = buffer:len()

    while pos < length do
        local internal_IEI = buffer(pos, 1):uint()
        local internal_IEI_upper_bits = bit.band(internal_IEI, 0xF0) -- extract the first 4 bits of the byte
        pos = pos + 1

        local internal_IEI_text = ""
        if internal_IEI_upper_bits == 128 or internal_IEI_upper_bits == 160 then
            internal_IEI_text = IEI_codes[internal_IEI_upper_bits]
        elseif internal_IEI >= 33 and internal_IEI <= 200 then
            internal_IEI_text = IEI_codes[internal_IEI]
        end

        if internal_IEI_text == "InReplyTo message ID" then
            subtree:add(InReplyToMessageID, buffer(pos, 16))
            pos = pos + 16

        elseif internal_IEI_text == "Application ID" then
            subtree:add(ApplicationID, buffer(pos, 16))
            pos = pos + 16

        elseif internal_IEI_text == "Sender MCData user ID" then
            pos = AddStringWithLength(buffer, subtree, SenderID, pos)

        elseif internal_IEI_text == "Application metadata container" then
            pos = AddStringWithLength(buffer, subtree, ApplicationMetadataContainer, pos)

        elseif internal_IEI_text == "Payload" then
            local payload_length =  buffer(pos, 2):uint() - 1
            pos = pos + 2
            local payload_type = PayloadContentType_codes[buffer(pos, 1):uint()]
            pos = pos + 1
            local payload_buf = buffer(pos, payload_length)
            if payload_type == "TEXT" then
                subtree:add(PayloadContentText, payload_buf)
            elseif payload_type == "BINARY" then
                subtree:add(PayloadContentBinary, payload_buf)
            elseif payload_type == "HYPERLINKS" then
                subtree:add(PayloadContentHyperlink, payload_buf)
            elseif payload_type == "FILEURL" then
                subtree:add(PayloadContentFileURL, payload_buf)
            elseif payload_type == "LOCATION" then
                -- Create a new subtree for Location
                local location_tree = subtree:add(PayloadContentLocation, buffer:range(pos, payload_length))
                location_tree:add(PayloadContentLatitude, buffer(pos, 3), DecodeLatitude(buffer(pos, 3):uint()))
                location_tree:add(PayloadContentLongitude, buffer(pos + 3, 3), DecodeLongitude(buffer(pos + 3, 3):uint()))
            elseif payload_type == "ENHANCED STATUS" then
                subtree:add(PayloadContentEnhancedStatus, payload_buf)
            elseif payload_type == "LOCATION ALTITUDE" then
                subtree:add(PayloadContentAltitude, payload_buf)
            elseif payload_type == "LOCATION TIMESTAMP" then
                subtree:add(PayloadContentTimestamp, payload_buf)
            elseif payload_type == "CODED TEXT" then
                subtree:add(PayloadContentCodedText, payload_buf)
            end
            pos = pos + payload_length

        elseif internal_IEI_text == "Metadata" then
            pos = AddStringWithLength(buffer, subtree, Metadata, pos)

        elseif internal_IEI_text == "Security parameters and Payload" then
            local field_length = buffer(pos, 2):uint()
            pos = pos + 2
            AppendSecurityParametersAndPayload(buffer, subtree, pos, field_length, off_network)
            pos = pos + field_length

        elseif internal_IEI_text == "Recipient MCData user ID" then
            pos = AddStringWithLength(buffer, subtree, RecipientID, pos)

        elseif internal_IEI_text == "Extended application ID" then
            pos = AddStringWithLength(buffer, subtree, ExtendedApplicationID, pos)

        elseif internal_IEI_text == "User location" then
            pos = AddStringWithLength(buffer, subtree, UserLocation, pos)

        elseif internal_IEI_text == "SDS disposition request type" then
            local disposition_type = bit.band(internal_IEI, 0x0F)
            -- aggiungo un valore "custom" (il buffer serve a Wireshark per fare l'highlight)
            subtree:add_packet_field(DispositionRequest, buffer(pos - 1, 1), disposition_type)

        elseif internal_IEI_text == "FD disposition request type" then
            local disposition_type = bit.band(internal_IEI, 0x0F)
            -- aggiungo un valore "custom" (il buffer serve a Wireshark per fare l'highlight)
            subtree:add_packet_field(DispositionRequestFD, buffer(pos - 1, 1), disposition_type)

        elseif internal_IEI_text == "Mandatory download" then
            local mandatory_download = bit.band(internal_IEI, 0x0F)
            -- aggiungo un valore "custom" (il buffer serve a Wireshark per fare l'highlight)
            subtree:add_packet_field(MandatoryDownload, buffer(pos - 1, 1), mandatory_download)

        end
    end
end

function AppendSecurityParametersAndPayload(buffer, subtree, pos, field_length, off_network)
    local start_pos = pos

    local message_type_buf = buffer(pos, 1)
    pos = pos + 1
    local datetime_buf = buffer(pos, 5)
    pos = pos + 5
    local payload_id_buf = buffer(pos, 4)
    pos = pos + 4
    local payload_seq_num_buf = buffer(pos, 1)
    pos = pos + 1
    local payload_algorithm_buf = buffer(pos, 1)
    pos = pos + 1
    --[[ Opzionale a specifica, noi non lo mettiamo
    local signalling_algorithm_buf = buffer(pos, 1)
    pos = pos + 1
    ]]--
    local iv_buf = buffer(pos, 16)
    pos = pos + 16
    local dppkid_buf = buffer(pos, 4)
    pos = pos + 4
    local payload_type_buf = buffer(pos, 1)
    pos = pos + 1
    local payload_length = buffer(pos, 2):uint()
    pos = pos + 2
    local payload_buf = buffer(pos, payload_length)
    pos = pos + payload_length

    local mikey_sakke_i_message_length = 0
    local mikey_sakke_i_message_buf
    if off_network == true then
        mikey_sakke_i_message_length = buffer(pos, 2):uint()
        pos = pos + 2
        mikey_sakke_i_message_buf = buffer(pos, mikey_sakke_i_message_length)
        pos = pos + mikey_sakke_i_message_length
    end

    if field_length == 0 then
        field_length = pos
    end

    -- Create a new subtree for Security Parameters And Payload
    local security_tree = subtree:add(SecurityParametersAndPayload, buffer(start_pos, field_length))
    security_tree:add(MessageType, message_type_buf)
    security_tree:add(DateTime, datetime_buf, CalculateNSTime(datetime_buf)):append_text(" (" .. datetime_buf:uint64() .. ")")
    security_tree:add(PayloadID, payload_id_buf)
    security_tree:add(PayloadSequenceNumber, payload_seq_num_buf)
    security_tree:add(PayloadAlgorithm, payload_algorithm_buf)
    -- security_tree:add(SignallingAlgorithm, signalling_algorithm_buf)
    security_tree:add(IV, iv_buf)
    security_tree:add(DPPK_ID, dppkid_buf)
    security_tree:add(ProtectedPayloadType, payload_type_buf)
    security_tree:add(ProtectedPayload, payload_buf)

    if off_network == true then
        security_tree:add(MIKEY_SAKKE_I_MESSAGE, mikey_sakke_i_message_buf)
    end
end

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

function DecodeLatitude(lat_raw)
    -- Split sign (Bit 23) and Magnitude N (Bits 0-22)
    local lat_sign = bit.rshift(lat_raw, 23)  -- 0 = North (+), 1 = South (-)
    local lat_N = bit.band(lat_raw, 0x7FFFFF) -- Mask out the highest bit

    -- 3GPP TS 23.032 formula: Lat = (90 / 2^23) * N
    local lat_val = (90 / 8388608) * lat_N
    if lat_sign == 1 then
        lat_val = -lat_val
    end

    return lat_val
end

function DecodeLongitude(lon_raw)
    -- Convert 24-bit 2's complement representation to signed integer
    local lon_N = lon_raw
    if bit.band(lon_raw, 0x800000) ~= 0 then
        lon_N = lon_N - 0x1000000 -- Subtract 2^24 to handle 2's complement
    end

    -- 3GPP TS 23.032 formula: Long = (360 / 2^24) * N
    local lon_val = (360 / 16777216) * lon_N

    return lon_val
end

DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-signalling", mcdata_protocol.dissector)
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-payload", mcdata_protocol.dissector)
