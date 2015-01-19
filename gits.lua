-- gits.lua
-- A wireshark plug-in to reverse engineer PwnAdventure 3 traffic
--
-- http://pwnadventure.com/ for more information.
--
-- eric.gragsone@erisresearch.org

gits_proto=Proto("GitS", "Pwn Adventure 3")

function addLocation(tvb, pos, tree)
  local branch
  
  branch=tree:add(tvb(pos,12), "Location")
  branch:add(tvb(pos,4), "X Coordinates: "..tvb(pos,4):le_uint())
  branch:add(tvb(pos+4,4), "Y Coordinates: "..tvb(pos+4,4):le_uint())
  branch:add(tvb(pos+8,4), "Z Coordinates: "..tvb(pos+8,4):le_uint())
end

function gits_proto.dissector(tvb,pinfo,tree)
  local code
  local pos
  local subtree
  local branch
  local stub
  local length
  local unknown
  local i
  
  unknown=0
  pos=0
  subtree=tree:add(gits_proto, tvb(), "PWN Adventure 3")

  while (tvb(pos,2):le_uint() == 0) do
	length=tvb(pos+2,2):le_uint()
	stub=subtree:add(tvb(pos+4,length), "Incoming chat: \""..tvb(pos+4,length):string().."\"")
	pos=pos+4+length
  end
  
  while pos < tvb:len()-1 do
    code=tvb(pos,2):le_uint()
	
	if (code == 0x0000) then
	  stub=subtree:add(tvb(pos,2), "Padding")
	  pos=pos+2
    elseif (code == 0x18e2) and (tvb:len() >= pos+7) then
	  stub=subtree:add(tvb(pos,7), "Unknown Code 0x18e2")
	  stub:add(tvb(pos+2,1), "Unknown: "..tvb(pos+2,1):le_int())
	  stub:add(tvb(pos+3,4), "Unknown: "..tvb(pos+3,4):le_int())
	  pos=pos+7
	  unknown=0
	elseif (code == 0x2b2b) and (tvb:len() >= pos+10) then
	  stub=subtree:add(tvb(pos,10), "Unknown Code 0x2b2b: "..tvb(pos+2,4):le_uint())
	  stub:add(tvb(pos+6,4), "Unknown: "..string.format('%08x ', tvb(pos+6,4):le_uint()))
	  pos=pos+10
	  unknown=0
	elseif (code == 0x2a23) and (tvb:len() >= pos+4) then
	  length=tvb(pos+2,2):le_uint()
	  
	  if (tvb:len() >= pos+4+length) then
	    stub=subtree:add(tvb(pos+4,length), "Chat: \""..tvb(pos+4,length):string().."\"")
		pos=pos+length
	  end
	  
	  pos=pos+4
	  unknown=0
	elseif (code == 0x3d71) and (tvb:len() >= pos+4) then
	  length=tvb(pos+2,2):le_uint()
	  
	  if (tvb:len() >= pos+4+length) then
	    stub=subtree:add(tvb(pos+4,length), "Zone: \""..tvb(pos+4,length):string().."\"")
		pos=pos+length
	  end
	  
	  pos=pos+4
	  unknown=0
	elseif (code == 0x3d73) and (tvb:len() >= pos+3) then
	  stub=subtree:add(tvb(pos,3), "Unknown Code 0x3d73: "..string.format('%08x ', tvb(pos+2,1):le_uint()))
	  pos=pos+3
	  unknown=0
	elseif (code == 0x616d) and (tvb:len() >= pos+6) then
	  branch=subtree:add(tvb(pos,6), "Mana: "..tvb(pos+2,4):le_uint())
	  pos=pos+6
	  unknown=0
	elseif (code == 0x635e) and (tvb:len() >= pos+6) then
	  stub=subtree:add(tvb(pos,3), "Unknown Code 0x635e: "..tvb(pos+2,4):le_uint())
	  pos=pos+6
	  unknown=0
	elseif (code == 0x636e) and (tvb:len() >= pos+8) then
	  length=tvb(pos+6,2):le_uint()
	  
	  if (tvb:len() >= pos+8+length) then
	    stub=subtree:add(tvb(pos,8+length), "Player: \""..tvb(pos+8,length):string().."\"")
	    stub:add(tvb(pos+2,4), "Player ID: "..tvb(pos+2,4):le_uint())
	    pos=pos+length+2
	  end
	  
	  length=tvb(pos+6,2):le_uint()
	  
	  if (tvb:len() >= pos+8+length) then
		stub:add(tvb(pos+8,length), "Team: \""..tvb(pos+8,length):string().."\"")
	    pos=pos+length+2
	  end
	  
	  pos=pos+6
	  
	  stub:add(tvb(pos,1), "Unknown: "..tvb(pos,1):uint())
	  stub:add(tvb(pos+1,4), "Unknown: "..tvb(pos+1,4):uint())
	  stub:add(tvb(pos+5,4), "Unknown: "..tvb(pos+5,4):uint())
	  stub:add(tvb(pos+9,4), "Unknown: "..tvb(pos+9,4):uint())
	  stub:add(tvb(pos+13,4), "Unknown: "..tvb(pos+13,4):uint())
	  pos=pos+17
	  
	  addLocation(tvb,pos,stub)
	  pos=pos+12
	  stub:add(tvb(pos,2), "Unknown: "..tvb(pos,2):uint())
	  stub:add(tvb(pos+2,2), "Unknown: "..tvb(pos+2,2):uint())
	  stub:add(tvb(pos+4,2), "Unknown: "..tvb(pos+4,2):uint())
	  pos=pos+6
	  
	  length=tvb(pos,2):le_uint()
	  
	  if(length > 0) then
	    stub:add(tvb(pos+2,length), "Unknown: "..tvb(pos+2,length):string())
	  end
	  
	  pos=pos+2+length
	  
      stub:add(tvb(pos,4), "Health?: "..tvb(pos,4):le_uint())
	  branch=stub:add(tvb(pos+4,2), "Actions?: "..tvb(pos+4,2):le_uint())
	  pos=pos+6
	  
	  for i=1, tvb(pos-2,2):le_uint() do
	    length=tvb(pos,2):le_uint()
	    branch:add(tvb(pos+2,length), "Action: "..tvb(pos+2,length):string())
		pos=pos+2+length
		pos=pos+1
	  end
	  
	  unknown=0
    elseif (code == 0x692a) and (tvb:len() >= pos+16) then
	  length=tvb(pos+2,2):le_uint()
	  
	  if (tvb:len() >= pos+4+length) then
	    stub=subtree:add(tvb(pos,16+length), "Player Attack: \""..tvb(pos+4,length):string().."\"")
		pos=pos+length
	  end
	   
	  stub:add(tvb(pos+4,4), "Unknown (c06ae400): "..string.format('%08x ', tvb(pos+4,4):le_uint()))
	  stub:add(tvb(pos+8,2), "Unknown (Related to player direction): "..tvb(pos+8,2):le_uint())
	  stub:add(tvb(pos+10,2), "Unknown (431d): "..string.format('%08x ', tvb(pos+10,2):le_uint()))
	  stub:add(tvb(pos+12,4), "Often Zero: "..string.format('%08x ', tvb(pos+12,4):le_uint()))
	  
	  pos=pos+16
	  unknown=0
	elseif (code == 0x6970) and (tvb:len() >= pos+8) then
	  length=tvb(pos+6,2):le_uint()
	  
	  if (tvb:len() >= pos+8+length) then
	    stub=subtree:add(tvb(pos,8+length), "Attack: \""..tvb(pos+8,length):string().."\"")
	    stub:add(tvb(pos+2,4), "Player ID: "..tvb(pos+2,4):le_uint())
	    pos=pos+length
	  end
	  
	  pos=pos+8
	  unknown=0
	elseif (code == 0x6b6d) and (tvb:len() >= pos+35) then
      length=tvb(pos+11,2):le_uint()
	  
	  if (tvb:len() >= pos+35+length) then
	    branch=subtree:add(tvb(pos,29+length), "Object: \""..tvb(pos+13,length):string().."\"")
	    branch:add(tvb(pos+2,4), "Object ID: "..tvb(pos+2,4):le_uint())
		branch:add(tvb(pos+6,4), "Player ID: "..tvb(pos+6,4):le_uint())
		branch:add(tvb(pos+10,1), "Often Zero: "..string.format('%08x ', tvb(pos+10,1):uint()))
		pos=pos+length+13
		
		addLocation(tvb, pos, branch)
		pos=pos+12
		
		branch:add(tvb(pos,4), "Unknown: "..string.format('%08x ', tvb(pos,4):uint()))
		branch:add(tvb(pos+4,2), "Often Zero: "..string.format('%08x ', tvb(pos+4,2):uint()))
		branch:add(tvb(pos+6,2), "Health: "..tvb(pos+6,2):le_uint())
		branch:add(tvb(pos+8,2), "Often Zero: "..string.format('%08x ', tvb(pos+8,2):uint()))
	    pos=pos+10
	  end
	  unknown=0
	elseif (code == 0x706a) and (tvb:len() >= pos+3) then
	  stub=subtree:add(tvb(pos,3), "Unknown Code 0x706a: "..string.format('%08x ', tvb(pos+2,1):le_uint()))
	  pos=pos+3
	  unknown=0
	elseif (code == 0x7274) and (tvb:len() >= pos+12) then
	    length=tvb(pos+6,2):le_uint()
	  
	    if (tvb:len() >= pos+8+length) then
		  branch=subtree:add(tvb(pos+12,length), "Unknown: \""..tvb(pos+8,length):string().."\"")
		  branch:add(tvb(pos+2,4), "Player ID: "..tvb(pos+2,4):le_uint())
	      pos=pos+length+8
	    end
		
		branch:add(tvb(pos,4), "Padding?: "..string.format('%08x ', tvb(pos,4):uint()))
		pos=pos+4
		unknown=0
	elseif (code == 0x7473) and (tvb:len() >= pos+8) then
	  length=tvb(pos+6,2):le_uint()
	  
	  if (tvb:len() >= pos+8+length) then
	    stub=subtree:add(tvb(pos,8+length), "Action: \""..tvb(pos+8,length):string().."\"")
	    stub:add(tvb(pos+2,4), "Player ID: "..tvb(pos+2,4):le_uint())
	    pos=pos+length
	  end
	  
	  pos=pos+8
	  pos=pos+1 -- padding, or null termination??
	  unknown=0
	elseif (code == 0x766d) and (tvb:len() >= pos+22) then
  	  stub=subtree:add(tvb(pos,22), "Player Info")
	  
	  if(pinfo.src_port > 3000) and (pinfo.src_port < 4000) then
	    stub:add(tvb(pos+2,4),"Player ID: "..tvb(pos+2,4):le_uint())
	    pos=pos+4
	  end
	  
	  addLocation(tvb, pos+2, stub)
	  stub:add(tvb(pos+14,4), "Direction: "..tvb(pos+14,4):le_int())
	  
	  if(pinfo.src_port > 3000) and (pinfo.src_port < 4000) then
	    stub:add(tvb(pos+18,2), "Unknown either 0x00, 0x7f,or 0x81 (Pitch?): "..string.format('%08x ', tvb(pos+18,2):le_uint()))
	    pos=pos+2
	  else
	    stub:add(tvb(pos+18,4), "Unknown either 0x00, 0x7f,or 0x81 (Pitch?): "..string.format('%08x ', tvb(pos+18,4):le_uint()))
		pos=pos+4
	  end
	  
	  pos=pos+18
	  unknown=0
	elseif (code == 0x7670) and (tvb:len() >= pos+3) then
	  if tvb(pos+2,1):le_uint() == 0 then
	    stub=subtree:add(tvb(pos,17), "PvP Flag: Disabled")
      elseif tvb(pos+2,1):le_uint() == 1 then
	    stub=subtree:add(tvb(pos,17), "PvP Flag: Enabled")
	  else
	    stub=subtree:add(tvb(pos,17), "PvP Flag: Unknown value"..string.format('%08x ', tvb(pos+2,1):le_uint()))
	  end
	  pos=pos+3
	  unknown=0
	elseif (code == 0x7070) and (tvb:len() >= pos+32) then
	  stub=subtree:add(tvb(pos,32), "Player ID: "..tvb(pos+2,4):le_uint())
	  addLocation(tvb, pos+6, stub)
	  stub:add(tvb(pos+18,4), "Relative direction: "..tvb(pos+18,4):le_int())
	  stub:add(tvb(pos+22,10), "Unknown: "..string.format('%08x ', tvb(pos+22,2):le_uint())..string.format('%08x ', tvb(pos+24,4):le_uint())..string.format('%08x ', tvb(pos+28,4):le_uint()))
	  pos=pos+32
	  unknown=0
	elseif (code == 0x7370) and (tvb:len() >= pos+30) then
	  stub=subtree:add(tvb(pos,30), "Entity ID: "..tvb(pos+2,4):le_uint())
	  addLocation(tvb, pos+6, stub)
	  stub:add(tvb(pos+18,2), "Often Zero: "..string.format('%08x ', tvb(pos+18,2):le_uint()))
	  stub:add(tvb(pos+20,2), "Unknown: "..string.format('%08x ', tvb(pos+20,2):le_uint()))
	  stub:add(tvb(pos+22,2), "Often Zero: "..string.format('%08x ', tvb(pos+22,2):le_uint()))
	  stub:add(tvb(pos+24,2), "Unknown: "..tvb(pos+24,2):le_int())
	  stub:add(tvb(pos+26,2), "Unknown: "..tvb(pos+26,2):le_int())
	  stub:add(tvb(pos+28,2), "Often Zero: "..string.format('%08x ', tvb(pos+28,2):le_uint()))
	  pos=pos+30
	  unknown=0
	elseif (code == 0x7878) and (tvb:len() >= pos+6) then
	  stub=subtree:add(tvb(pos,6), "Remove Entity: "..tvb(pos+2,4):le_int())
	  pos=pos+6
	  unknown=0
	else
	  if (unknown == 0) then
	    stub=subtree:add(tvb(pos), "Unknown Code "..string.format('%08x ', code))
		unknown=1
	  end
	  pos=pos+1
	end
  end
end

prot_table = DissectorTable.get("tcp.port")
prot_table:add(3000,gits_proto) -- Gold Farm
prot_table:add(3001,gits_proto) -- Unbearable Woods
prot_table:add(3002,gits_proto) -- Balmer Peak
prot_table:add(3003,gits_proto)
prot_table:add(3004,gits_proto)
prot_table:add(3005,gits_proto)
prot_table:add(3006,gits_proto)
prot_table:add(3007,gits_proto)
prot_table:add(3008,gits_proto)
prot_table:add(3009,gits_proto) -- Tall Mountains
prot_table:add(3010,gits_proto)
prot_table:add(3011,gits_proto)
prot_table:add(3012,gits_proto)
prot_table:add(3013,gits_proto)
prot_table:add(3014,gits_proto) -- Pirate Bay
prot_table:add(3015,gits_proto)