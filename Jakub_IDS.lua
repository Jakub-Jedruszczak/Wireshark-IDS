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
	if text ~= nil then 
		if type(text) == "table" then
			for k, v in pairs(text) do
				if type(v) == "table" then
					for k_, v_ in pairs(v) do
						__DEBUG_OUTPUT = __DEBUG_OUTPUT .. "        " ..  k_ .. ": " .. v_ .. "\n"
					end
				else
					__DEBUG_OUTPUT = __DEBUG_OUTPUT .. "    " ..  k .. ": " .. v .. "\n"
				end
			end
			__DEBUG_OUTPUT = __DEBUG_OUTPUT .. "\n"
		else
			__DEBUG_OUTPUT = __DEBUG_OUTPUT .. text .. "\n"
		end
	end
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


--------------------------------------------------------------------------------
-- This function loads the signatures from a CSV file into Wireshark's memory.
-- I decided to use the SNORT signature format for compatibility and so that
-- users don't have to learn a new format. This doesn't use the ReadCSV function
-- since simple pattern matching is not enough to properly parse the format.
--------------------------------------------------------------------------------

function SignatureReader(filename)
	local file = io.open(path .. filename, "r")
	if not file then 
		printd("Error: Unable to open file " .. filename)
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
			printd("Error: Signature does not contain SID.")
		end
	end

	file:close()

	return data
end



function ToBytes(content) -- makes all the `content` searches uniform by converting them all into bytes
	content = content:sub(0, content:find('"')-1) -- only the part in quotes incasse it was parsed wrong earlier
	local result = ""
	-- main loop - I tried using patterns but it did not work for every test case
	local inPipes = false
	for i = 1, #content do
		local char = content:sub(i, i)
		-- Checking if we're in the pipe brackets
		if char == "|" and inPipes == false then
			inPipes = true
			goto continue
		
		elseif char == "|" and inPipes == true then
			inPipes = false
			goto continue
		end
		
		-- Handling hex data
		if inPipes == true then
			if char ~= " " then
				result = result .. char
			end
		-- Handling ascii data
		else
			result = result .. string.format("%02X", string.byte(char)) -- formats the chatacter as a byte
		end
		::continue::
	end
return result
end


--------------------------------------------------------------------------------
-- This function loads the signatures from a CSV file into Wireshark's memory.
-- I decided to use the SNORT signature format for compatibility and so that
-- users don't have to learn a new format. This doesn't use the ReadCSV function
-- since simple pattern matching is not enough to properly parse the format.
--------------------------------------------------------------------------------


function ReadBlacklist(filename)
	local file = io.open(path .. filename, "r") -- Open the file
	if not file then
		printd("Error: Unable to open file " .. filename)
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
			printd("Error: Unable to parse line: " .. line)
		end
	end

	file:close()

	return data
end


function SaveBlacklist(filename) -- saves the blacklist to a file
	-- Assessing if an entry should remain in the blacklist
	-- Using Meng et al.'s IP confidence equation
	for ip, values in pairs(blacklisted_IPs) do
		local IP_confidence = values[1] / (10 * values[2])
		if IP_confidence >= 1 then
			blacklisted_IPs[ip] = nil
		end
	end

	-- Ssaving to file
	local file = io.open(path .. filename, "w")
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


--------------------------------------------------------------------------------
-- My implementation of Wu-Manber for multiple pattern searching. This uses 
-- similar techniques to Boyer-Moore but applies it to multiple patterns at a
-- time. This makes content matching potentially MUCH faster than normal.
--------------------------------------------------------------------------------


function HashPattern(pattern, start_index, end_index) -- sismple hash function for speed
	local hash = 0
	for index = start_index, end_index - 1 do
		hash = hash * 256 + pattern:byte(index)
	end
	return hash
end


function WuManber(text, patterns)
	local text_length = #text
	local subpatterns = 2 -- number of subpatterns to split each pattern into; 2 is the standard for Wu-Manber

	-- Iterate through each pattern
	for pattern_key, pattern in pairs(patterns) do
		local pattern_length = #pattern

		-- Define the length of each subpattern
		local subpattern_length = math.floor(pattern_length / subpatterns) -- equivalent to python's  `pattern_length // subpatterns` (integer division)

		-- Initialize the hash values for each subpattern
		local subpattern_hashes = {}
		for i = 1, subpatterns do
			local start_index = (i - 1) * subpattern_length + 1
			local end_index = i * subpattern_length
			subpattern_hashes[i] = HashPattern(pattern, start_index, end_index)
		end

		-- Initialize the shift value for each subpattern
		local subpattern_shifts = {}
		for i = 1, subpatterns do
			subpattern_shifts[i] = subpattern_length * (subpatterns - i)
		end

		-- Iterate through the text (the hard part)
		for i = 1, text_length - pattern_length + 1 do
			-- Check if the subpatterns match
			local subpatterns_match = true
			for j = 1, subpatterns do
				local start_index = i + (j - 1) * subpattern_length
				local end_index = i + j * subpattern_length - 1
				if HashPattern(text, start_index, end_index) ~= subpattern_hashes[j] then
					subpatterns_match = false
					break
				end
			end

			if subpatterns_match then
				-- If the subpatterns match, check if the full pattern matches
				if text:sub(i, i + pattern_length - 1) == pattern then
					return {1, pattern_key}  -- Direct match found, return 1 and pattern key
				end
			end

			-- Shift the pattern by the appropriate amount
			local shift_applied = false
			for j = 1, subpatterns do
				if i + subpattern_shifts[j] <= text_length - pattern_length + 1 then
					i = i + subpattern_shifts[j]
					shift_applied = true
					break
				end
			end

			if not shift_applied then
				i = i + 1
			end
		end
	end
	-- No match found, return -1
	return {-1, -1}
end



--[[
-- TESTING!!!!!!!!!!!!!!!!!!!!!!!!!!!

local patterns = {["A"] = "4FFFFB824FFFFB824FFFFB824FFFFB82",
["B"] = "9090909090909090909090909090",
["C"] = "03E0F82503E0F82503E0F82503E0F825",
["D"] = "A61CC013A61CC013A61CC013A61CC013",
["E"] = "801C4011801C4011801C4011801C4011",
["F"] = "13C01CA613C01CA613C01CA613C01CA6",
["F"] = "56A57763",
["G"] = "08210280082102800821028008210280",
["H"] = "8210201791D02008",
["I"] = "909090E8C0FFFFFF2F62696E2F7368",
["J"] = "B0B5CD80",
["K"] = "240F1234240F1234240F1234240F1234",
["L"] = "0B3902800B3902800B3902800B390280",
["M"] = "B017CD80",
["N"] = "47FF041F47FF041F47FF041F47FF041F",
["O"] = "7569643D3028726F6F7429"}
local result = WuManber("000400010006005056A577630000080045C00040EF14000001598A620A285501E00000050201002CC0A8F1F300000000EAD800000000000000000000FFFFFF00000A0201000000280A28550100000000", patterns)
printd(result) -- expected result: {1, "F"}

--]]


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
		SaveBlacklist("blacklist.csv")
		timer = current_time
	end


	-- Analysing the packet
	local sp = pinfo.src_port
	local reason = ""
	local is_sus = 0

	local result = IDS(tvb, pinfo, tree)

	if result[1] == 1 then -- 1 means it matched
		BadPacketCount = BadPacketCount + 1
		is_sus = "Suspicious"
		if signatures[result[2]] ~= nil then
			reason = "The packet triggered rules SID: " .. result[2] .. "  (\"" .. signatures[result[2]]["options"]["msg"] .. ")"

		else
			reason = "Unkown signature was matched."
		end
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
	tree:set_generated()
end


--------------------------------------------------------------------------------
-- The main function for the IDS to work; this function determines if a packet
-- is suspicious or not.
--------------------------------------------------------------------------------

BadPacketCount = 0 -- for debugging and evaluation

frame_protocols_f = Field.new("frame.protocols") -- For finding the highest protocol in the stack, e.g. "tcp" in the stack "eth:ethertype:ip:tcp"

blacklisted_IPs = ReadBlacklist("blacklist.csv") -- I know using globals is not great but this makes stuff easier

signatures = SignatureReader("jakub.rules") -- loading signatures

all_sids = {} -- need a table of all signature IDs

for key, _ in pairs(signatures) do
	all_sids[key] = key
end


function IDS(tvb, pinfo, tree)
	-- pinfo.in_error_pkt shows if the packet is an error packet
	 if pinfo.in_error_pkt then
		return -1
	 end

	-- Secondly checking for blacklisted IP addresses; inspired by Meng et al.'s (2014) work at reducing false positive rates
	local ip_src = tostring(pinfo.src)
	local result = {}

	if blacklisted_IPs[ip_src] ~= nil then
		-- Call SignatureCheck() using the signatures that match for the IP address
		local result = SignatureCheck(tvb, pinfo, tree, blacklisted_IPs[ip_src][3])
		if result[1] == 1 then
			-- A signature has matched
			return {1, result[2]}
		end
		result = SignatureCheck(tvb, pinfo, tree, all_sids)
		if  result[1] == 1 then
			-- A signature has matched
			return {1, result [2]}
		else
			-- No signatures have matched
			return {-1}
		end


	else -- if the source IP is not in the blacklist
		local result = SignatureCheck(tvb, pinfo, tree, all_sids)
		if result[1] == 1 then
			-- A signature has matched
			return {1, result[2]}
		else
			-- No signatures have matched
			return {-1}
		end
	end
end

--------------------------------------------------------------------------------
-- This is the function that checks the signatures; it goes over all of the
-- ones that don't have a `contents` option first to determine if either 
-- Wu-Manber or Boyer-Moore-Horspool is necessary.
--------------------------------------------------------------------------------

function SignatureCheck(tvb, pinfo, tree, sigs)
	--[[
	count the number of signatures that match (based on just the normal parts of the signature, not the contents/options)
	if the number is past a threshold of maybe 10, then use Wu-Manber to check the contents; otherwise use Boyer-moore-Horspool

	LOGIC:
	- Check if the normal parameters (ports, IP, etc) are matching the signature
	- If the signature has no contents/ other options (and it matches), perform a signature check on the signature (this is pretty much done at this point so return {1, sid}? )
	- If there is a contents option, then add one to the MatchedContentSigs variable
	- If the variable gets to like 15, then do Wu-Manber
	- If it parsed all the sigs and there werent 15 or more content-optioned sigs then do Boyer-Moore-Horspool
	--]]
	sigs = sigs or all_sids

	local MatchingSignatureCount = 0
	local MatchingSignatureTable = {}
	local WuManberThreshold = 15 -- arbitrary number


	for tmp, sid in pairs(sigs) do
		local signature = signatures[sid]
		if signature == nil then -- must be an error or something
			goto SkipSignature
		end
		-- Implementation of Figure 4.4
		-- Check if the protocol matches the signature's protocol
		if string.find(tostring(frame_protocols_f()), signature["protocol"]) == nil then
			goto SkipSignature
		end
		-- Check if packet ports match signature ports
		if signature["source port"] ~= "any" and signature["source port"] ~= tostring(pinfo.src_port) then
			goto SkipSignature
		end
		if signature["destination port"] ~= "any" and signature["destination port"] ~= tostring(pinfo.dst_port) then
			goto SkipSignature
		end
		-- Check if signature has contents to check for - don't check them yet though!
		if signature["options"]["content"] ~= nil then
			MatchingSignatureCount = MatchingSignatureCount + 1
			MatchingSignatureTable[sid] = signature["options"]["content"]
			if MatchingSignatureCount > WuManberThreshold then
				goto EndDSALoop
			end
			goto SkipSignature -- needed because we haven't checked if the content actually matches yet
		end
		-- this means the packet matches the signature
		-- log the packet
		do -- `return` statements need to be in some kind of conditional otherwise you can't add anything after them
			LogAlert(tvb, tree, pinfo, sid)
			return {1, sid}
		end

		------------------------------------------------------------------------------------------------------------------------------------------------------
		-- This is stil part of the loop so that if it fails then it keeps going with the loop
		::EndDSALoop::
		local first_145_bytes = tostring(tvb:range(0, math.min(tvb:len(), 145)):bytes())

		-- Checking if Wu-Manber or Boyer-Moore-Horspool should be used
		if MatchingSignatureCount > WuManberThreshold then
			-- Do Wu-Manber
			-- TODO: Do Wu-Manber
			local result = WuManber(first_145_bytes, MatchingSignatureTable)
			if result[1] == 1 then
				return {1, result[2]}
			end
		else
			-- Do Boyer-Moore-Horspool
			for sid_, content in pairs(MatchingSignatureTable) do
				if BoyerMooreHorspool(first_145_bytes, content) == 1 then
					return {1, sid_}
				end
			end
		end
		::SkipSignature::
	end
	-- No signature matched, increase good packet count by 1
	if blacklisted_IPs[tostring(pinfo.src)] ~= nil then
		blacklisted_IPs[tostring(pinfo.src)] = {blacklisted_IPs[tostring(pinfo.src)][1] + 1, blacklisted_IPs[tostring(pinfo.src)][2], blacklisted_IPs[tostring(pinfo.src)][3]}
	end
	return {-1}
end



--[[
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
	end
	-- No signature matched, increase good packet count by 1
	if blacklisted_IPs[tostring(pinfo.src)] ~= nil then
		blacklisted_IPs[tostring(pinfo.src)] = {blacklisted_IPs[tostring(pinfo.src)][1] + 1, blacklisted_IPs[tostring(pinfo.src)][2], blacklisted_IPs[tostring(pinfo.src)][3]}
	end
	return {-1}
end


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
	-- Check if packet ports match signature ports
	if signature["source port"] ~= "any" and signature["source port"] ~= tostring(pinfo.src_port) then
		return {-1}
	end
	if signature["destination port"] ~= "any" and signature["destination port"] ~= tostring(pinfo.dst_port) then
		return {-1}
	end
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
--]]


--------------------------------------------------------------------------------
-- These functions create menus in the Tools menu to browse the IP blacklist
-- and the rule set. This helps with debugging both for myself and for users of
-- the plugin.
--------------------------------------------------------------------------------


local function ShowBlacklist()
	local tw = TextWindow.new("IP Blacklist")
	local text = "Bad packet count: " .. BadPacketCount .. "\n\n" -- output; starts off with the number of total bad packets
	tw:add_button("Clear Blacklist", function()
		BadPacketCount = 0
		for ip, _ in pairs(blacklisted_IPs) do
			blacklisted_IPs[ip] = nil
			tw:clear()
		end
	 end)

	for ip, data in pairs(blacklisted_IPs) do
		text = text .. "\nIP address: " .. ip .. "\n"
		text = text .. "  Good Packet Count: " .. data[1] .."\n"
		text = text .. "  Bad Packet Count: " .. data[2] .. "\n"
		text = text .. "  IP Confidence: " .. string.format("%.3f", tostring(data[1] / (10 * data[2]))) .. "\n" -- Meng et al.'s IP confidence equation rounded to 3 d.p.
		text = text .. "  Matched Signatures:\n"
		for _, sid in ipairs(data[3]) do
			text = text .. "    - ".. sid .. "\n"
		end
	end
	tw:append(text)
end

register_menu("IP Blacklist", ShowBlacklist, MENU_TOOLS_UNSORTED)


local function ShowAlerts()
	local tw = TextWindow.new("Alert Log")
	local text = ""
	tw:add_button("Clear Log", function()
		io.open(path .. "alert.log","w"):close() -- clear alert log file
			tw:clear()
	 end)
	local file = io.open(path .. "alert.log")
	text = file:read("*a") -- "*a" reads the entire file
	io.close(file)

	-- Format text
	text = text:gsub("\n", "\n\n")
	local parts = {}
	for part in text:gmatch("%s%[") do
		table.insert(parts, part)
	end

	local formatted = text:gsub("%s%[", "\n[")

	tw:set(formatted)
end

register_menu("Alert Log", ShowAlerts, MENU_TOOLS_UNSORTED)


local function ShowSignatures(sid)
	local tw = TextWindow.new("Signatures")
	local txt = ""
	tw:set_atclose(function() txt = "" end)
	if signatures then
		-- Display the parsed signatures
		if sid == "ALL" then
			for sid_, signature in pairs(signatures) do
				txt = txt .. "Signature SID " .. sid_ .. ":\n"
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
				txt = txt .. "\n"
			end
		else
			if signatures[sid] == nil then txt = "No signatures found or error occurred while parsing signatures." return end
			txt = txt .. "Signature SID " .. sid .. ":\n"
			for key, value in pairs(signatures[sid]) do
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


local SID_d = ""
function ShowSignaturesDialog(SID_d)
	function ShowSignaturesDialog_(SID_d)
		ShowSignatures(SID_d)
	end
	new_dialog("Enter SID", ShowSignaturesDialog_, "SID ('ALL' for all signatures):")
end


register_menu("Signatures", ShowSignaturesDialog, MENU_TOOLS_UNSORTED)



--------------------------------------------------------------------------------
-- The logging function; this logs the alerts in standard SNORT format. Useful
-- for making the tool compatible with other systems, for example SIEM systems.
-- Because the format is going to be near identical, no extra parsing tools
-- should be needed (hopefully). Note that this isn't SNORT's only output type,
-- however it is the easiest to read for humans and therefore easier to debug.
--------------------------------------------------------------------------------

function LogAlert(tvb, tree, pinfo, sid)
	-- Updating Blacklist
	if blacklisted_IPs[tostring(pinfo.src)] ~= nil then
		blacklisted_IPs[tostring(pinfo.src)] = {blacklisted_IPs[tostring(pinfo.src)][1], blacklisted_IPs[tostring(pinfo.src)][2] + 1, blacklisted_IPs[tostring(pinfo.src)][3]}
	else
		blacklisted_IPs[tostring(pinfo.src)] = {0, 1, {sid}}
	end

	-- Adding alert to log file
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


	local file = io.open(path .. "alert.log", "a")
	if not file then
		printd(path .. "alert.log could not be opened")
	end
	file:write(output)
	file:close()
	
	return output
end

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