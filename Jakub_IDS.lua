-- Jakub_IDS.lua
--------------------------------------------------------------------------------
--[[
 _____                                             _____ 
( ___ )                                           ( ___ )
 |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   | 
 |   |  ,-_/     .       .     ,-_/ .-,--.  .---.  |   | 
 |   |  '  | ,-. | , . . |-.   '  | ' |   \ \___   |   | 
 |   |     | ,-| |<  | | | |   .^ | , |   /     \  |   | 
 |   |     | `-^ ' ` `-^ ^-'   `--' `-^--'  `---'  |   | 
 |   |  /` |                                       |   | 
 |   |  `--'                                       |   | 
 |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___| 
(_____)                                           (_____)

	This is an IDS created to work with Wireshark using various open source
	signature databases. This plugin is intended to work with offline network
	traffic captures, but it may be adjusted to work with real-time inputs.
--]]
--------------------------------------------------------------------------------

local my_info = {
    version = "1.0.0",
    author = "Jakub Jedruszczak",
    repository = "https://github.com/Jakub-Jedruszczak/Wireshark-IDS",
    spdx_id = "GPL-2.0-or-later",
    description = "A threat detection engine for Wireshark."
}

set_plugin_info(my_info)


--------------------------------------------------------------------------------
-- Debug output logging. Used to print some debugging information - since
-- regular print() doesn't actually do anything.
--------------------------------------------------------------------------------

__DEBUG_OUTPUT = ""

function DebugMenu()
	local tw = TextWindow.new("DEBUG")
	tw:append(__DEBUG_OUTPUT)
end

register_menu("Debug Menu", DebugMenu, MENU_TOOLS_UNSORTED)

function printd(text)
	__DEBUG_OUTPUT = __DEBUG_OUTPUT .. text .. "\n"
end




--------------------------------------------------------------------------------
-- This function loads the signatures from a CSV file into Wireshark's memory.
-- I decided to use the SNORT signature format for compatibility and so that
-- users don't have to learn a new format. This doesn't use the ReadCSV function
-- since simple pattern matching is not enough to properly parse the format.
--------------------------------------------------------------------------------

function SignatureReader(filename)
	local file = io.open(path .. filename, "r")
	if not file then 
		print("Error: Unable to open file " .. filename)
		return nil 
	end

	local data = {}

	for line in file:lines() do
		local signature = {}

		-- Extracting individual components from the signature - thank god for line breaks
		local action, protocol, source, source_port, direction, destination, destination_port, options = 
			line:match("(%w+)%s+(%w+)%s+(%S+)%s+(%S+)%s+([%-<>]+)%s+(%S+)%s+(%S+)%s+%((.*)%)")

		if not action then
			file:close()
			return "Error: Unable to parse line: " .. line
		end

		-- Setting up key-value pairs
		signature["action"] = action
		signature["protocol"] = protocol
		signature["source address"] = source
		signature["source port"] = source_port
		signature["direction"] = direction
		signature["destination address"] = destination
		signature["destination port"] = destination_port

		-- Parsing options into a table
		local options_table = {}
		for key, value in options:gmatch("(%w+):\"?([^;]+)\"?;") do
			if key == "content" then -- normalising content matching into bytes
				value = ToBytes(value)
			end
			options_table[key] = value
			if key == "sid" then
				signature["sid"] = value
			end
		end
		signature["options"] = options_table

		-- Inserting the signature into the data table with SID as key
		if signature["sid"] then
			data[signature["sid"]] = signature
		else
			print("Error: Signature does not contain SID.")
		end
	end

	file:close()

	return data
end


--[[
	************* TESTING *******************
local filename = "rules.txt"
local signatures = SignatureReader(filename)

if signatures then
	-- Display the parsed signatures
	for sid, signature in pairs(signatures) do
		print("Signature SID " .. sid .. ":")
		for key, value in pairs(signature) do
			if type(value) == "table" then -- multi-valued inputs
				io.write("  " .. key .. ": {")
				for k, v in pairs(value) do
					io.write(k .. "=" .. v .. ",")
				end
				print("}")
			else
				print("  *" .. key .. "*: " .. value)
			end
		end
	end
else
	print("No signatures found or error occurred while parsing signatures.")
end
--]]





function ToBytes(content)
	content = content:sub(0, content:find('"')-1) -- only the part in quotes incasse it was parsed wrong earlier
	print(content)
	local result = ""
	-- main loop - I tried using patterns but it did not work for every test case
	local inPipes = false
	for i = 1, #content do
		local char = content:sub(i, i)
		print(char)
		-- Checking if we're in the pipe brackets
		if char == "|" and inPipes == false then
			print("in pipes")
			inPipes = true
			goto continue
		
		elseif char == "|" and inPipes == true then
			print("left pipes")
			inPipes = false
			goto continue
		end
		
		-- Handling hex data
		if inPipes == true then
			print("doing some plumbing")
			if char ~= " " then
				result = result .. char
			end
		-- Handling ascii data
		else
		print("hammer time")
			result = result .. string.format("%02X", string.byte(char))
		end
		::continue::
		print("end loop")
	end
return result
end

--[[
	********TESTING*********
str = "ABCD|0F A1|HELLO\",distance 0,nocase"
result = ToBytes(str)
print(result)
--]]





--------------------------------------------------------------------------------
-- This function loads the signatures from a CSV file into Wireshark's memory.
-- I decided to use the SNORT signature format for compatibility and so that
-- users don't have to learn a new format. This doesn't use the ReadCSV function
-- since simple pattern matching is not enough to properly parse the format.
--------------------------------------------------------------------------------


function ReadBlacklist(filename)
	local file = io.open(path .. filename, "r") -- Open the file
	if not file then 
		print("Error: Unable to open file " .. filename)
		return nil
	end

	local data = {} -- Table to store the blacklisted IP addresses

	for line in file:lines() do -- Iterate over each line in the file
		local ip, good_packets, bad_packets, matched_signatures = line:match("(%S+)%s*,%s*(%d+)%s*,%s*(%d+)%s*,%s*(.*)")
		if ip then
			local matched_signatures_table = {}
			for signature_id in matched_signatures:gmatch("(%d+)%s*") do
				table.insert(matched_signatures_table, signature_id)
			end
			data[ip] = {tonumber(good_packets), tonumber(bad_packets), matched_signatures_table}
		else
			print("Error: Unable to parse line: " .. line)
		end
	end

	file:close() -- Close the file

	return data -- Return the parsed blacklisted IP addresses
end


--[[
	******************** TESTING ************************
local filename = "blacklist.csv"
local blacklist = ReadBlacklist(filename)

-- Print the parsed blacklisted IP addresses
for ip, data in pairs(blacklist) do
	print("IP address:", ip)
	print("  Good Packet Count:", data[1])
	print("  Bad Packet Count:", data[2])
	print("  Matched Signatures:")
	for _, signature_id in ipairs(data[3]) do
		print("    -", signature_id)
	end
end
--]]

function SaveBlacklist(filename)
	local file = io.open(path .. filename, "w") -- Open the file for writing
	if not file then 
		printd("Error: Unable to open file " .. filename .. " for writing")
		return -1
	end

	for ip, values in pairs(blacklisted_IPs) do
		local good_packets = values[1]
		local bad_packets = values[2]
		local matched_signatures = table.concat(values[3], " ") -- love this new function

		file:write(ip .. "," .. good_packets .. "," .. bad_packets .. "," .. matched_signatures .. "\n")
	end

	file:close() -- Close the file
end

--------------------------------------------------------------------------------
-- This creates the dialogue menu for changing the path to the file
-- to be loaded. This is necessary because my way of guessing the Plugin folder
-- path may not be accurate, so changing this is pretty important in order for
-- the program to work. Opens 'README.md' to confirm that the path works.
--------------------------------------------------------------------------------

-- Define the menu entry's callback
local function dialog_menu()
    local function dialog_func(p)
        local window = TextWindow.new("Change the Plugin Folder Path")
        local message = string.format("New path is %s\nIf this is correct, press Confirm.\nIf it works, the README should be printed\n", p)
        window:set(message)
        window:add_button("Confirm", function()
            path = p:gsub('\\', '\\\\') -- replaces all single slashes with a double slash
            local f = io.open(p .. "README.md", "r")
            io.input(f)
            content = io.read("*a") -- "*a" reads the entire file
            io.close(f)
            window:append(content)
        end)
    end

    new_dialog("Change Path to Plugin Folder",dialog_func,"Current path: " .. path .. "\n\nNew path (End input in backslash):")
end

-- Create the menu entry
register_menu("Change Path to Plugin Folder", dialog_menu, MENU_TOOLS_UNSORTED)

--------------------------------------------------------------------------------
-- This generates the plugin folder path from the major, minor and micro version
-- numbers. The micro version is not in the folder name if it's 0, which is 
-- accounted for with the if statement.
--------------------------------------------------------------------------------

-- Get version for automatically detecting the file path
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")

-- Loads a file
-- local default_path = "C:\\Program Files\\Wireshark\\plugins\\4.2\\" -- my personal path
if micro == "0" then 
    path = "C:\\Program Files\\Wireshark\\plugins\\" .. major .. "." .. minor .. "\\"
else 
    path = "C:\\Program Files\\Wireshark\\plugins\\" .. major .. "." .. minor ..  "." .. micro .. "\\"
end
f = io.open(path .. "README.md", "r")
io.input(f)
content = io.read("*a") -- "*a" reads the entire file
io.close(f)

signatures = SignatureReader("jakub.rules") -- loading signatures

--------------------------------------------------------------------------------
-- Opens 'README.md' on loading Wireshark to confirm that the file loading
-- functionality works correctly. This entire project relies on loading external
-- files, so this is pretty important!
--------------------------------------------------------------------------------

local graphic = [[
  _____                                                                                                                  _____ 
 ( ___ )                                                                                                                 ( ___ )
 |       |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|       | 
 |       |      ,-_/                .                  .              ,-_/     .-,--.       .---.                      |       | 
 |       |        '  |      ,-.      |   ,     .    .     |--.        '      |     '   |   \     \___                    |        | 
 |       |           |     ,--|      |<      |    |    |     |       .^   |    ,    |   /            \                 |        | 
 |       |           |     `-^     '   `      `--^   ^--'       `---'    `-^--'         `---'                  |        | 
 |       |        /` |                                                                                                    |        | 
 |       |        `--'                                                                                                    |        | 
 |_____|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|_____|
 (_____)                                                                                                                (_____)

]]




-- Notify the user that the menu was created
if gui_enabled() then
   local splash = TextWindow.new("Hello!");
   splash:set(graphic)
   splash:append("Hello! This is a test of file loading; if it works, the README should be printed. If this is not the case, go to Tools > Change Path To Plugin Folder")
   splash:append("\nThe current version is " .. major .. "." .. minor .. "." .. micro .. "\n")
   splash:append(content .. "\n")
end


--------------------------------------------------------------------------------
-- The main post-dissector of the plugin; this runs for every packet in order to
-- analyse the packets.

-- (Adapted from https://wiki.wireshark.org/Lua/Examples/PostDissector)
-- (partially)
--------------------------------------------------------------------------------




-- we create a "protocol" for our tree
local sus_p = Proto("suspiciousness","A measure of how suspicious the packet is")

-- we create our fields
local sus_field = ProtoField.string("Suspiciousness")
local sus_reason_field = ProtoField.string("Reason")

-- we add our fields to the protocol
sus_p.fields = {sus_field}

-- then we register sus_p as a postdissector
register_postdissector(sus_p)


timer = 0 -- for checking when the timer is more than 5 seconds to update the blacklist

-- main post-dissector
function sus_p.dissector(tvb,pinfo,tree)
	-- Blacklist updating
	local current_time = pinfo.rel_ts
	if current_time - timer > 5 then
		printd(current_time - timer)
		SaveBlacklist("blacklist.csv")
		timer = current_time
	end


	-- Analysing the packet
	local sp = pinfo.src_port
	local reason = ""
	local is_sus = 0

	local result = IDS(tvb, pinfo, tree)

	if result[1] == 1 then -- 1 means it matched
		is_sus = "Suspicious"
		reason = "The packet triggered rules SID: " .. result[2]
	else
		is_sus = "Benign"
		reason = "The packet did not trigger any rules."
		if result[2] ~= nil then
			reason = reason .. "\n()" .. result[2] .. ")"
		end
	end

	if pinfo.in_error_pkt then -- return value for error packets
		reason = "ERROR PACKET"
		is_sus = "ERROR"
	end

	-- I would love to be able to colourise the packets if they're suspicious but apparently that's not possible
	-- (https://osqa-ask.wireshark.org/questions/9511/is-it-possible-to-set-the-coloring-of-a-packet-from-a-dissector/)
	tree:add(sus_field, is_sus)
	tree:add_le(sus_reason_field, reason)
	--tree:add(sus_reason_field, reason)
	tree:set_generated()
end

--------------------------------------------------------------------------------
-- An implementation of Boyer-Moore-Horspool for string searching. It uses the
-- Bad Match heuristic to generate a table which reduces the time complexity of
-- the search from O((length of text - length of pattern +1) * length of pattern)
-- to O(length of text * length of pattern), but in reality it's even better
-- since it can skip over characters and blocks of text (Wheeler, 2006). Cool!
--------------------------------------------------------------------------------

function BadMatch(pattern) -- builds the bad match table
	local bad_match = {}
	local pattern_length = string.len(pattern)
	local last_char = string.sub(pattern, pattern_length, pattern_length)
	
	for i = 1, pattern_length - 1 do
		local char = string.sub(pattern, i, i)
		bad_match[char] = pattern_length - i
	end
	
	-- Assign default shift value based on last character
	bad_match[last_char] = pattern_length
	
	return bad_match
end

function BoyerMooreHorspool(text, pattern)
	-- Quite proud of how simple it is honestly
	local bad_match = BadMatch(pattern)
	local text_length = string.len(text)
	local pattern_length = string.len(pattern)
	local i = pattern_length
	
	while i <= text_length do
		local j = pattern_length
		local k = i -- index (I already used 'i', so 'k' it is)
		
		while j > 0 and string.sub(text, k, k) == string.sub(pattern, j, j) do
			j = j - 1 -- as far as I know Lua has no 'j ++' or 'j += 1' operators
			k = k - 1
		end
		
		if j == 0 then
			return k + 1  -- pattern found at index k in text
		else
			local char = string.sub(text, i, i)
			i = i + (bad_match[char] or pattern_length) -- neat little line
		end
	end
	
	return -1  -- pattern not found in text
end

--[[
	************TESTING*****************
local text = "this is a test string for testing the Boyer-Moore-Horspool algorithm"
local pattern = "Horspool"

local index = BoyerMooreHorspool(text, pattern)

if index ~= -1 then
	print("Pattern found at index:", index)
else
	print("Pattern not found in text.")
end

--]]


--------------------------------------------------------------------------------
-- The main function for the IDS to work; this function determines if a packet
-- is suspicious or not.
--------------------------------------------------------------------------------

--[[
	TODO:
	*MAKE SIGNATURES*
	- Need to make signatures for detecting sus activity
	- Need easy format: maybe NAME, PROTOCOL, TYPE (length check, header check, etc), VALUE TO CHECK AGAINST, PRIORITY???

	*ALERT AND LOGGING*
	- Output file which will store alerts
	- Use a standard format so that it can be integrated into SIEMs

	*BLACKLIST-BASED IP FILTER*
	- Load IP Blacklist as a table
		- FORMAT: {IP address:[good packet count, bad packet count, [matched signatures] ]}
	- Every 5 seconds or so, check if an IP still belongs in the blacklist (see Meng et al. 2014)
		- pinfo.rel_ts shows the relative time of the packet from when capture started
	- Do the signatures that the source IP matched on in the past
		- If it matches the signature(s), then mark as suspicious, add to the number of bad packets recieved, and mark as suspicious
		- If it doesn't match any signatures, pass it to the NIDS for further inspection
	
	*MAIN IDS*
	- Look for stuff that shows the packet doesn't need to be analysed (i.e, TCP flags, stuff like that)
	- Check what signature sets to apply to the packet based on protocol/ port
	- Check against the signatures using technqiues below

	*CHECKING FOR SIGNATURE MATCHES*
	- tvb:__tostring() converts the bytes of the tvb into a string (said to be used mostly for debugging)
	- tvb:raw() apparently also does something like this
	- Boyer-Moore is good for medium-to-long signatures in long text
			- Maybe use Boyer-Moore-Horspool like Snort: its simplified and only uses one table
	- Maybe use a different one for very short (1-3 byte) signatures
	- If a signature matches, add IP to blacklist along with all the signatures it matched
	- If no signature matches and the IP is in the blacklist, add one to the number of good packets
	- If no sig. matches and it isn't in the blacklist, mark as benign and let it go
			- Do not add one to it's blacklist as it shouldn't exit yet, plus adding it would make no sense
]]

-- each entry will have the following format:
-- key: Source IP; Contents: array [bad packets, good packets]

frame_protocols_f = Field.new("frame.protocols") -- For finding the highest protocol in the stack, e.g. "tcp" in the stack "eth:ethertype:ip:tcp"

blacklisted_IPs = ReadBlacklist("blacklist.csv")


function IDS(tvb, pinfo, tree)
	--[[
	RETURN VALUES:
		-1 = error packet; mark as error
		>1 = suspicious
		0  = benign

	IDENTIFIED PROTOCOLS:
		- HTTP: a HTTP request packet
		- data-text-lines: A HTTP response packet
		- data: can be ICMP packets, "portmap" packets, TCP packets, NFS packets
		- SLL: Linux Cooked-Mode Capture, essentially a bypass of Linux not dealing with libpcap well
		- RPC: 
		- MOUNT: 
		- BITTORRENT: 
		- SSH: 
		- POP: 
		- IMAP: 
		- IMF: Internet message format, another mail protocol built alongside SMTP
		- NFS: Network File System, probably worth checking this for malware
		- 
	
	EXAMPLE SIGNATURES:
		- Large ICMP/ping packets are VERY suspicious, do a length check, for example with bytearray:len()
		- Frequency of packets, detecting DoS/ port scanning
		- SSL/TLS check for HTTPS - don't scan much of those packets since they're encrypted
		- Check for IPSec? Those are also encrypted
		- 
	]]

	-- Firstly checking for flags and such that would make analysing the packet unnecessary
	-- Routine protocols like ARP; probably better to do statistical sigs for them anyway
	-- Encrypted protocols
	-- Whitelists?
	-- Internal network traffic - gotta be careful with this
	-- (Do it here)

	-- pinfo.in_error_pkt shows if the packet is an error packet
	 if pinfo.in_error_pkt then
		return -1
	 end

	-- Secondly checking for blacklisted IP addresses; inspired by Meng et al.'s (2014) work at reducing false positive rates
	-- Expand blacklisted IPs with blacklisted user agents? (for HTTP(S) packets)
	local ip_src = tostring(pinfo.src)
	local result = {}

	if blacklisted_IPs[ip_src] ~= nil then
		-- Call SignatureCheck() using the signatures that match for the IP address
			-- If any of the signatures match, return "suspicious" and increment the number of bad packets; send
				-- Also log the alert
			-- If the packet doesn't match any signatures, send it to the rest of the signatures
		local result = MultiSigCheck(tvb, pinfo, tree, blacklisted_IPs[ip_src])
		if result[1] == 1 then
			-- A signature has matched
			return {1, result[2]}
		end
		result = MultiSigCheck(tvb, pinfo, tree, {"ALL"})
		if  result[1] == 1 then
			-- A signature has matched
			return {1, result [2]}
		else
			-- No signatures have matched
			return {-1}
		end


	else -- if the source IP is not in the blacklist
		local result = MultiSigCheck(tvb, pinfo, tree, {"ALL"})
		if result[1] == 1 then
		-- Call SignatureCheck() using all the signatures
			-- If any of the signatures match, return "suspicious" and add the source IP to the blacklist and add the signature to the blacklist too
				-- Also log the alert
			-- If the packet doesn't match any signatures, its benign
			-- A signature has matched
			return {1, result[2]} -- ?
		else
			-- No signatures have matched
			return {-1}
		end
	end
end


function MultiSigCheck(tvb, pinfo, tree, sigs)
	-- Check here for multiple signatures
	-- Multiple calls to SignatureCheck()
	-- (Basically a for loop going over all the signatures passed in through the args)
	-- Return signatures matched (or better to do it directly here?), true/false
	if sigs[#sigs] == "ALL" then
		-- do all the signatures
		for sid, _ in pairs(signatures) do
			local result = SignatureCheck(tvb, pinfo, tree, sid)
			if result[1] == 1 then
				return {1, result[2]}
			end
		end
	else
		for sid, _ in pairs(signatures) do
			local result = SignatureCheck(tvb, pinfo, tree, sid)
			if result[1] == 1 then
				return {1, result[2]}
			end
		end
		--[[
		-- do the signatures in the signatures arg
		for k, sid in pairs(sigs) do
			local result = SignatureCheck(tvb, pinfo, tree, sid)
			if result[1] == 1 then
				return {1, sid}
			end

		end
		--]]
	end
	-- No signature matched, increase good packet count by 1
	if blacklisted_IPs[tostring(pinfo.src)] ~= nil then
		blacklisted_IPs[tostring(pinfo.src)] = {blacklisted_IPs[tostring(pinfo.src)][1] + 1, blacklisted_IPs[tostring(pinfo.src)][2], blacklisted_IPs[tostring(pinfo.src)][3]}
	end
	return {-1}
end






-- TODO: MAKE THE SIG CHECK FUNCTIONS RETURN THE SIDS OF MATCHED SIGNATURES
-- ALL PACKETS ARE MARKED AS SUSPICIOUS
-- ADD IP TO BLACKLIST/ INCREMENT VALUE










function SignatureCheck(tvb, pinfo, tree, sid)
	-- Check here for individual signatures -- Boyer-Moore-Horspool
	-- pinfo.match_string - "Matched string for calling subdissector from table."
	-- Signature format (copied from SNORT for compatibility): ACTION, PROTOCOL, SOURCE_IP, SOURCE_PORT, DIRECTION, DESTINATION_IP, DESTINATION_PORT, (MSG/ OPTION)
												   -- Example: alert      tcp      any         21          ->        10.199.12.8           any        (msg:"TCP packet is detected"; content:"USER root";)
	-- return true/false
	local signature = signatures[sid]
	-- Implementation of Figure 4.4
	if string.find(tostring(frame_protocols_f()), signature["protocol"]) == nil then
		return {-1}
	end
	--if (tostring(pinfo.src_port) ~= signature["source port"] and tostring(pinfo.src_port) ~= "any") or (tostring(pinfo.dst_port) ~= signature["destination port"] and tostring(pinfo.dst_port) ~= "any") then
	--	return {-1}
	--end
	if signature["options"]["content"] ~= nil then
		-- content matching here
		-- Boyer-Moore-Horspool since it is a single signature search
		local first_145_bytes = tostring(tvb:range(0, math.min(tvb:len(), 145)):bytes()) -- Wheeler (2006) says that only 145 bytes are needed to check 95% of SNORT rules
		if BoyerMooreHorspool(first_145_bytes, signature["options"]["content"]) == -1 then
			return {-1}
		end
	end
	-- this means the packet matches the signature
	-- log the packet
	if blacklisted_IPs[tostring(pinfo.src)] ~= nil then
		blacklisted_IPs[tostring(pinfo.src)] = {blacklisted_IPs[tostring(pinfo.src)][1], blacklisted_IPs[tostring(pinfo.src)][2] + 1, blacklisted_IPs[tostring(pinfo.src)][3]}
	else
		blacklisted_IPs[tostring(pinfo.src)] = {0, 1, {sid}}
	end
	LogAlert(tvb, tree, pinfo, sid)
	return {1, sid}
end



--------------------------------------------------------------------------------
-- These functions create menus in the Tools menu to browse the IP blacklist
-- and the rule set. This helps with debugging both for myself and for users of
-- the plugin.
--------------------------------------------------------------------------------


local function ShowBlacklist()
	local tw = TextWindow.new("IP Blacklist")
	local text = "" -- output
	for ip, data in pairs(blacklisted_IPs) do
		text = text .. "IP address:" .. ip .. "\n"
		text = text .. "  Good Packet Count:" .. data[1] .."\n"
		text = text .. "  Bad Packet Count:" .. data[2] .. "\n"
		text = text .. "  Matched Signatures: \n"
		for _, sid in ipairs(data[3]) do
			text = text .. "    - ".. sid .. "\n"
		end
	end
	tw:append(text)
end

register_menu("IP Blacklist", ShowBlacklist, MENU_TOOLS_UNSORTED)


local function ShowSignatures()
	local tw = TextWindow.new("Signatures")
	local txt = ""
	if signatures then
		-- Display the parsed signatures
		for sid, signature in pairs(signatures) do
			txt = txt .. "Signature SID " .. sid .. ":\n"
			for key, value in pairs(signature) do
				if type(value) == "table" then -- multi-valued inputs
					txt = txt .. "  " .. key .. ": {\n"
					for k, v in pairs(value) do
						txt = txt .. "          " .. k .. "=" .. v .. "\n"
					end
					txt = txt .. "  }\n"
				else
					txt = txt .."  " .. key .. ": " .. value .. "\n"
				end
			end
		end
	else
		txt = "No signatures found or error occurred while parsing signatures."
	end
	tw:append(txt)

	function remove() -- called when the menu is closed
		txt = ""
		tw:clear()
	end

	tw:set_atclose(remove)

end

register_menu("Signatures", ShowSignatures, MENU_TOOLS_UNSORTED)



--------------------------------------------------------------------------------
-- The logging function; this logs the alerts in standard SNORT format. Useful
-- for making the tool compatible with other systems, for example SIEM systems.
-- Because the format is going to be near identical, no extra parsing tools
-- should be needed (hopefully). Note that this isn't SNORT's only output type,
-- however it is the easiest to read for humans and therefore easier to debug.
--------------------------------------------------------------------------------

function LogAlert(tvb, tree, pinfo, sid)
	local sig = signatures[sid]
	local output = ""
	output = output .. "[**] [1:" .. sid .. ":" .. sig["options"]["rev"].. "] " -- rule header
	output = output .. sig["action"] .. " " .. sig["protocol"] .. " " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) -- action, prot, source address/port
	output = output .. " " .. sig["direction"] .. " " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) -- direction, destination address/port
	output = output .. " " .. sig["options"]["msg"]:sub(1, -2) .. " [**] " -- message and rule header ending
	output = output .. "[Classification: " .. tostring(sig["options"]["classtype"]) .. "] " -- rule classification / metadata
	output = output .. "[Priority: 1] " -- rule priority - the plugin currently doesn't calculate/ parse the priority correctly/ at all
	output = output .. pinfo.abs_ts -- timestamp (relative to the start of the capture because of Wireshark baloney)
	output = output .. "\n"

	--printd(output) -- debug print
	local file = io.open(path .. "alert.log", "a")
	if not file then
		printd(path .. "alert.log could not be opened")
	end
	file:write(output)
	file:close()
	
	return output
end