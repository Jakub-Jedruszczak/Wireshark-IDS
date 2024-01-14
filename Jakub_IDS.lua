--------------------------------------------------------------------------------
-- This creates the dialogue menu for changing the path to the file
-- to be loaded. This is necessary because my way of guessing the Plugin folder
-- path may not be accurate, so changing this is pretty important in order for
-- the program to work. Opens 'hi.txt' to confirm that the path works.
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
-- This generates the plugin folder from the major, minor and micro version
-- numbers which are used for the plugin folder. The micro version is not in the
-- folder name if it's 0, which is accounted for with the if statement.
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
   splash:set("Hello! This is a test of file loading; if it works, the README should be printed. If this is not the case, go to Tools > Change Path To Plugin Folder\nThe current version is " .. major .. "." .. minor .. "." .. micro .. "\n")
   splash:append(content)
end
