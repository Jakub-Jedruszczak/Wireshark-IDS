-- Jakub_IDS.lua
--------------------------------------------------------------------------------
--[[
    This is an IDS created to work with Wireshark using various open source
    signature databases. This plugin is intended to work with offline network
    traffic captures, but it may be adjusted to work with real-time inputs.
-- ]]
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
-- local default_path = "C:\\Program Files\\Wireshark\\plugins\\4.2\\" -- my path
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
-- Opens 'hi.txt' on loading Wireshark to confirm that the file loading
-- functionality works correctly. This entire project relies on loading external
-- files, so this is pretty important!
--------------------------------------------------------------------------------

-- Notify the user that the menu was created
if gui_enabled() then
   local splash = TextWindow.new("Hello!");
   splash:set("Hello! This is a test of file loading; if it works, the README should be printed. If this is not the case, go to Tools > Change Path To Plugin Folder")
   splash:append("\nThe current version is " .. major .. "." .. minor .. "." .. micro .. "\n")
   splash:append(content)
end

--------------------------------------------------------------------------------
-- A simple tap/ listener used as a proof of concept and an attempt at filtering
-- packets and acting upon their data. This menu presents all packets with a TCP
-- port of 80, 433, or 8080. It shows the number of times these packets came 
-- from a source address as well as the overall count of filter-matching packets.
-- (Adapted from :https://www.wireshark.org/docs/wsdg_html_chunked/wslua_tap_example.html)
--------------------------------------------------------------------------------

local function counting_tap()
	-- Declare the window we will use
	local tw = TextWindow.new("Address Counter")

	-- This will contain a hash of counters of appearances of a certain address
	local ips = {}
    local counter = 0 -- total packet count

	-- this is our tap
	local tap = Listener.new(nil, "tcp.port in {80, 443, 8080}");

	local function remove()
		-- this way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- we tell the window to call the remove() function when closed
	tw:set_atclose(remove)

	-- this function will be called once for each packet
	function tap.packet(pinfo, tvb)
        local key = tostring(pinfo.src)
    
        if ips[key] == nil then
            ips[key] = {0, tostring(pinfo.src_port), tostring(pinfo.dst_port)}  -- Initialize with default values if the key doesn't exist
        end

        local count = ips[key][1]
        local s_port = ips[key][2]
        local d_port = ips[key][3]

        ips[key] = {count + 1, s_port, d_port}  -- Update the values
        counter = counter + 1
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()
        tw:append("Source IP\t\tCount\tSource Port \tDestination Port \t(Matching Packets:" .. counter ..")\n")
		for key, values in pairs(ips) do
			tw:append(key .. "\t" .. values[1] .. "\t" .. values[2] .. "\t\t" .. values[3] .."\n");
		end
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		ips = {}
        counter = 0
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- using this function we register our function
-- to be called when the user selects the Tools->Test->Packets menu
register_menu("Test/Packets", counting_tap, MENU_TOOLS_UNSORTED)

--------------------------------------------------------------------------------
-- A simple tap to test packet dissection. This particular one extracts the URL
-- of packets from HTTP(s) traffic. 
--------------------------------------------------------------------------------

-- Creating a field reader before the listener is initalised
local uri = Field.new("http.request.uri")
local host = Field.new("http.host")

local function http_tap()
	-- Declare the window we will use
	local tw = TextWindow.new("Address Counter")

	-- This will contain a hash of counters of appearances of a certain address
	local websites = {}
    local counter = 0

	-- this is our tap
	local tap = Listener.new(nil, "http.request");

	local function remove()
		-- this way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- we tell the window to call the remove() function when closed
	tw:set_atclose(remove)

	-- this function will be called once for each packet
	function tap.packet(pinfo, tvb)
        local http_data = tvb:range():string()

        local uri = tostring(uri())
        local host = tostring(host())
        local ip = tostring(pinfo.src)
        websites[counter] = {ip, host, uri}
        counter = counter + 1
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()
        tw:append("Source IP\t\tHost\t\tWebsite\n")
		for key, values in pairs(websites) do
			tw:append(values[1].. "\t" .. values[2] .."\t" .. values[3] .. "\n");
		end
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		websites = {}
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- using this function we register our function
-- to be called when the user selects the Tools->Test->Packets menu
register_menu("Test/HTTP", http_tap, MENU_TOOLS_UNSORTED)


--------------------------------------------------------------------------------
-- An attempt to add another column to the main view, showing the URI of HTTP 
-- packets. This uses a post-dissector to modify the view as taps can't modify
-- the dissected packets. This is a dummy post-dissector that "checks" if a
-- packet is malicious by checking if the source port number is odd or even.

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


-- main post-dissector
function sus_p.dissector(tvb, pinfo, tree)

	local sp = pinfo.src_port
	local reason = ""
	is_sus = 0
	-- dummy check for if a packet is suspicious - even source port numbers and suspicious and vice versa
	if sp % 2 == 0 then
		is_sus = "Suspicious"
		reason = "How odd! This packet's source port number is even."
	else
		is_sus = "Benign"
		reason = "Nothing wrong with it."
	end

	-- I would love to be able to colourise the packets if they're suspicious but apparently that's not possible
	-- (https://osqa-ask.wireshark.org/questions/9511/is-it-possible-to-set-the-coloring-of-a-packet-from-a-dissector/)
    tree:add(sus_field, is_sus)
	tree:add_le(sus_reason_field, reason)
	--tree:add(sus_reason_field, reason)
	tree:set_generated()

