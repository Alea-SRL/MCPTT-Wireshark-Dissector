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

mcdata_protocol = Proto("mcdata",  "mcdata SIP Dissector")

local IEI_codes = {
    [1] = "SDS SIGNALLING PAYLOAD",
    [2] = "FD SIGNALLING PAYLOAD",
    [3] = "DATA PAYLOAD",
    [4] = "SDS NOTIFICATION",
    [5] = "FD NOTIFICATION",
    [6] = "SDS OFF-NETWORK MESSAGE",
    [7] = "SDS OFF-NETWORK NOTIFICATION",
    [8] = "FD NETWORK NOTIFICATION",
    [9] = "COMMUNICATION RELEASE",
    [10] = "DEFERRED LIST ACCESS REQUEST",
    [11] = "DEFERRED LIST ACCESS RESPONSE",
    [12] = "FD HTTP TERMINATION",
    [120] = "Payload"
}

local DispostionRequest_codes = {
    [0] = "NONE",
    [1] = "DELIVERY",
    [2] = "READ",
    [3] = "DELIVERY AND READ"
}

local PayloadContentType_codes = {
    [1] = "TEXT",
    [2] = "BINARY",
    [3] = "HYPERLINKS",
    [4] = "FILEURL",
    [5] = "LOCATION",
    [6] = "ENHANCED STATUS"
}



IEI = ProtoField.int8("mcdata.iei", "IEI", base.DEC, IEI_codes)
DateTime_i = ProtoField.uint64("mcdata.datetime_i", "DateTime", base.DEC)
DateTime = ProtoField.absolute_time("mcdata.datetime", "DateTime", base.LOCAL)
message_id = ProtoField.string("mcdata.message_id", "Message ID", base.ASCII)
conversation_id = ProtoField.string("mcdata.conversation_id", "Conversation ID")
DispostionRequest = ProtoField.uint8("mcdata.dispositionrequesttype", "Disposition Request Type", base.DEC, DispostionRequest_codes, 128)
PayloadsCount = ProtoField.uint8("mcdata.payload.count", "Number of payloads", base.DEC)
PayloadsTotalSize = ProtoField.uint16("mcdata.payload.TotalSize", "Length of Payload contents", base.DEC)
PayloadsContentType = ProtoField.uint8("mcdata.payload.contenttype", "Payload content type", base.DEC, PayloadContentType_codes)
PayloadsContentText = ProtoField.string("mcdata.payload.contentstring", "Payload content type string")




mcdata_protocol.fields = {IEI,DateTime_i,DateTime,message_id,conversation_id,DispostionRequest, PayloadsCount,PayloadsTotalSize,PayloadsContentType,PayloadsContentText}

function mcdata_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = mcdata_protocol.name

  local subtree = tree:add(mcdata_protocol, buffer(), "MCDATA Talkway")
  
  
  
  local IEI_number =  buffer(0,1):le_uint()
  local usecs = buffer(1,5):le_uint64()
-- gets the seconds as a Lua number
local secs  = (usecs):tonumber()
local nstime = NSTime.new(secs, 0)

-- add it to the tree, highlighting the real buffer's bytes, but with the real NSTime value

  
  subtree:add_le(IEI, buffer(0,1))
  
  if IEI_number > 0 and IEI_number < 12 then
  	if IEI_number == 1 then
      subtree:add_le(DateTime_i, buffer(1,5))

      subtree:add(DateTime, buffer(1,5), nstime)
      subtree:add(message_id, buffer(5,16))
      subtree:add(conversation_id, buffer(22,16))
	  subtree:add_le(DispostionRequest, buffer(38,1))
    end
    if IEI_number == 3 then

      subtree:add(PayloadsCount, buffer(1,1))
	  subtree:add(IEI, buffer(2,1))
	  
	  local IEI_Payload_number =  buffer(2,1):le_uint()
      local PayloadsCount_number =  buffer(1,1):le_uint()

  	  if IEI_Payload_number == 120 then
        subtree:add(PayloadsTotalSize, buffer(3,2))
        local PayloadsTotalSize_number =  buffer(3,2):int()
        debug("PayloadsTotalSize_number " .. PayloadsTotalSize_number)
                
        for i=1,PayloadsCount_number do
  			local payloadsubtree = subtree:add(mcdata_protocol, buffer(), "Payload")
 				  local payload_type =  buffer(5,1):le_uint()
  			      payloadsubtree:add(PayloadsContentType, buffer(5,1))
  			      if payload_type == 1 then
  			         payloadsubtree:add(PayloadsContentText, buffer(6,PayloadsTotalSize_number-1))
  			      end

		end
	  end
    end
  end


end

local dissectorTable = DissectorTable.get("media_type")

dissectorTable:add("application/vnd.3gpp.mcdata-signalling", mcdata_protocol.dissector)
dissectorTable:add("application/vnd.3gpp.mcdata-payload", mcdata_protocol.dissector)
