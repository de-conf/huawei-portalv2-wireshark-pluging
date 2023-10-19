--[[ huawei-portal-v2.lua    deconf  2023-10-08 ]]

-- script location:
-- linux: .local/lib/wireshark/plugins/
-- win: %APPDATA%\Wireshark\plugins

-- Define Huawei Portal Protocol
local p_huaweip = Proto("huaweip", "Huawei Protocol");

-- Define fields
-- field: version
local f_ver = ProtoField.uint8("huaweip.ver", "Version",base.HEX, {
		[0x02] = "Huawei 2",
	})

	
-- field: request/response type	
local action_val_map={
	[0x01] = "(1)REQ_CHALLENGE",
	[0x02] = "(2)ACK_CHALLENGE",
	[0x03] = "(3)REQ_AUTH",
	[0x04] = "(4)ACK_AUTH",
	[0x05] = "(5)REQ_LOGOUT",
	[0x06] = "(6)ACK_LOGOUT",
	[0x07] = "(7)AFF_ACK_ATH",
	[0x08] = "(8)NTF_LOGOUT",
	[0x09] = "(9)REQ_INFO",
	[0x0a] = "(10)ACK_INFO",
	[0x0b] = "(11)NTF_USRERDISCOVERY",
	[0x0c] = "(12)NTF_USERIPCHANGE",
	[0x0d] = "(13)AFF_NTF_USERIPCHANGE",
	[0x0e] = "(14)ACK_NTF_LOGOUT",
	[0x81] = "(129)WEB_STATUS_NOTIFY",
	[0x82] = "(130)WEB_ACK_STATUS_NOTIFY"
}
local f_type = ProtoField.uint8("huaweip.type", "type",base.HEX,action_val_map)


-- field: method
local f_method = ProtoField.uint8("huaweip.method", "method",base.HEX, {
		[0x00] = "CHAP",
		[0x01] = "PAP"
})


-- field: reserved
local f_Rsv = ProtoField.uint8("huaweip.Rsv", "Rsv",base.HEX, {
	[0x00] = "保留字段"
})

-- field: serial Number
local f_SerialNo = ProtoField.uint8("huaweip.SerialNo", "SerialNo",base.DEC)

-- field: request ID
local f_ReqID = ProtoField.uint8("huaweip.ReqID", "ReqID",base.DEC)
-- field: user IP
local f_UserIP = ProtoField.ipv4("huaweip.UserIP", "UserIP")

-- field: user port
local f_UserPort = ProtoField.uint8("huaweip.UserPort", "UserPort(no use)",base.DEC)


-- field: error code
local error_code_maps = {
    [0x02] = {
        [0x00] = "Challenge Success",
        [0x01] = "Challenge Reject",
        [0x02] = "Link Established",
        [0x03] = "In the Process of Certification",
        [0x04] = "Error (Challenge Failed)",
    },
    [0x04] = {
        [0x00] = "Authentication Successful",
        [0x01] = "Authentication Request Denied",
        [0x02] = "This Link Has Been Established",
        [0x03] = "Authentication Process, Please Try Again Later",
        [0x04] = "Authentication Error (Error Occurred)",
    },
    [0x05] = {
        [0x00] = "Offline Request",
        [0x01] = "Not Receive BAS Request Packet, Active Request Response",
    },
    [0x06] = {
        [0x00] = "Offline Successfully",
        [0x01] = "Offline Was Rejected",
        [0x02] = "Offline Failed (Occurred Error)",
        [0x03] = "User Already Offline",
    },
    [0x08] = {
        [0x00] = "User Already Offline",
    },
    [0x0a] = {
        [0x00] = "User Query Processed Successfully",
        [0x01] = "BAS: This Feature Is Not Supported",
        [0x02] = "BAS: Processing Failed for Some Unknown Reason",
    },
    [0x0d] = {
        [0x00] = "Update User IP Successfully",
        [0x01] = "Update User IP Failed",
    },
}

-- Create a function to get the error description based on f_type and f_ErrCode
local function getErrorDescription(f_type, f_ErrCode)
    local error_map = error_code_maps[f_type]
    if error_map then
        local error_description = error_map[f_ErrCode]
        if error_description then
            return error_description
		else
			return "Unknown Error Code"
        end
	else
		return "Error Code Not in Error Code Has Type Information"
    end 
end



local f_ErrCode = ProtoField.int8("huaweip.ErrCode", "ErrCode",base.DEC)

-- field: attribute number
local f_AttrNum = ProtoField.uint8("huaweip.AttrNum", "AttrNum",base.DEC)

-- field: authenticator
local f_AuthenticatorOut = ProtoField.bytes("huaweip.AuthenticatorOut", "AuthenticatorOut")

-- field: attribute type
local attr_val_map={
		[0x01] = "UserName",
		[0x02] = "PassWord",
		[0x03] = "Challenge",
		[0x04] = "ChapPassWord",
		[0x05] = "TextInfo",
		[0x06] = "UpLinkFlux",
		[0x07] = "DownLinkFlux",
		[0x08] = "Port",
		[0x09] = "IP_Config",
		[0x0a] = "BAS_IP",
		[0x0b] = "User_Mac",
		[0x0c] = "Delay_Time",
		[0x0d] = "User_Private_IP",
		[0xF0] = "CHAP_ID",
		[0xF1] = "User_IPV6",
		-- [0x40] = "WebAuthenInfo"
}
local f_attrType=ProtoField.uint32("huaweip.attrType", "attrType",base.HEX,attr_val_map)

-- field: whole attribute
local f_attr=ProtoField.none("huaweip.attr", "attr",base.HEX)

-- field: length of the attribute
local f_attrLen=ProtoField.uint32("huaweip.attrLen", "attrLen",base.DEC)

-- field: hex content of attribute
local f_attrContent=ProtoField.uint32("huaweip.f_attrContent", "f_attrContent",base.HEX)

-- field: string content of attribute
local f_attrStringContent=ProtoField.string("huaweip.attrStringContent", "attrStringContent")

-- declare all fields for the huawei protocol
p_huaweip.fields = { f_ver, f_type,f_method,f_Rsv,f_SerialNo, f_ReqID,f_UserIP,f_UserPort,f_ErrCode,f_AttrNum,f_AuthenticatorOut,f_attr,f_attrType,f_attrLen,f_attrContent ,f_attrStringContent}

local data_dis = Dissector.get("data")

function p_huaweip.dissector(buf, pkt, tree)
		-- local action_val_map={
		-- [2] = "(2) Action2",
		-- [3] = "(3)REQ_AUTH",
		-- [4] = "(4)ACK_AUTH",
		-- [5] = "(5)REQ_LOGOUT",
		-- [7] = "(7)AFF_ACK_ATH",
		-- [8] = "(8)NTF_LOGOUT",
		-- [9] = "(9)REQ_INFO"
			-- }
	
		-- add attributes to tree
        local subtree = tree:add(p_huaweip, buf(0))
        subtree:add(f_ver, buf(0,1))
        subtree:add(f_type, buf(1,1))
		subtree:add(f_method, buf(2,1))
		subtree:add(f_Rsv, buf(3,1))
		
		subtree:add(f_SerialNo, buf(4,2))
		subtree:add(f_ReqID, buf(6,2))
		subtree:add(f_UserIP, buf(8,4))
		subtree:add(f_UserPort, buf(12,2))

		--subtree:add(f_ErrCode, buf(14,1))
		local f_type_value = buf(1, 1):uint()
		local f_ErrCode_value = buf(14, 1):uint()
		local error_description = getErrorDescription(f_type_value, f_ErrCode_value)
		subtree:add(f_ErrCode, buf(14, 1)):append_text(" (" .. error_description .. ")")	
		subtree:add(f_AttrNum, buf(15,1))
		subtree:add(f_AuthenticatorOut, buf(16,16))
		
		-- subtree:add(f_method, buf(2,1))
		-- subtree:add(f_method, buf(2,1))
	
		local stringSwitch={
		[1] = "UserName",
		[2] = "PassWord",
		[5] = "TextInfo",
		}
		
		local macSwitch={
		[0x0b] = "User_Mac",
		}
		
        local attrNum = buf(15,1):uint()
		local pointer=32
		
		-- build tree for every attribute
		-- add every attribute to parent tree
		for i=1,attrNum do
			local attrType = buf(pointer,1)
			local attrLen=buf(pointer+1,1):uint()
			local attrTree=subtree:add(f_attr,buf(pointer,attrLen))
			
			attrTree:add(f_attrType,attrType )
			
			attrTree:add(f_attrLen,attrLen )
			local attrTypeForSwitch = buf(pointer,1):uint()
			
			
			local attrContent=buf(pointer+2,attrLen-2)
			
			if(stringSwitch[attrTypeForSwitch]) then
				attrTree:add(f_attrStringContent,attrContent )
			elseif (macSwitch[attrTypeForSwitch])then
				attrTree:add(f_attrStringContent,tostring( buf(pointer+2,attrLen-2):ether()))--tostring(attrContent:ether())
			else
				attrTree:add(f_attrContent,attrContent )--default
			end
			
			
			pointer=pointer+attrLen
			
		end
		
		--set info column as eg."(2) Action2 ...."
		if pkt.columns.info then
			pkt.columns.info:preppend(action_val_map[buf(1,1):uint()] .. " ")		
		end
		
		--set protocol column as "Huawei Protocol"
		if pkt.columns.protocol then
			pkt.columns.protocol:set("Huawei Protocol")
		end

end

-- grep the packet from udp port 2000 and 50100
local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(2000, p_huaweip)
udp_encap_table:add(50100, p_huaweip)
