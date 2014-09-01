-- XOR64
-- Used to decipher the command and control protocol of a specific malware
-- eric.gragsone@erisresearch.org

function bin_xor(x, y)
   local z = 0
   for i = 0, 31 do
      if (x % 2 == 0) then                      -- x had a '0' in bit i
         if ( y % 2 == 1) then                  -- y had a '1' in bit i
            y = y - 1 
            z = z + 2 ^ i                       -- set bit i of z to '1' 
         end
      else                                      -- x had a '1' in bit i
         x = x - 1
         if (y % 2 == 0) then                  -- y had a '0' in bit i
            z = z + 2 ^ i                       -- set bit i of z to '1' 
         else
            y = y - 1 
         end
      end
      y = y / 2
      x = x / 2
   end
   return z
end

function band(x,y)
   local z = 0
   for i = 0, 31 do
      if (x % 2 == 1) then                      -- x had a '0' in bit i
         x = x - 1
         if ( y % 2 == 1) then                  -- y had a '1' in bit i
            y = y - 1
            z = z + 2 ^ i                       -- set bit i of z to '1'
         end
      elseif ( y % 2 == 1) then
         y = y -1
      end
      y = y / 2
      x = x / 2
   end

   return z
end

xor_proto=Proto("xor64", "XORs packets using the first 64bits as the key.")

function xor_proto.dissector(tvb,pinfo,tree)
  local subtree
  local key
  local ctxt
  local ptxt
  local hexdump=''
  local message=''
  local pos

  if tvb:len() > 4 then
    pinfo.cols.protocol="XOR64"
    key=tvb(0,4):uint()
    pos=4

    if tvb:len() > 8 then
      for i=4,(tvb:len()-3),4 do
        pos=i
        ctxt=tvb(pos,4):uint()
        ptxt=bin_xor(key,ctxt)

        for j=1,4 do
          x=band(ptxt,0xff*256^(4-j))/256^(4-j)
          hexdump=hexdump..string.format('%08x ', ptxt)

          if x > 0x1f and x < 0x7f then
            message=message..string.char(x)
          else
            message=message..'.'
          end
        end
      end
      pos=pos+4
    end

    if pos+1<tvb:len() then
      ctxt=tvb(pos, tvb:len()-pos):uint()*256^(4+pos-tvb:len())
      ptxt=bin_xor(key,ctxt)

        for j=1,tvb:len()-pos do
          x=band(ptxt,0xff*256^(4-j))/256^(4-j)
          hexdump=hexdump..string.format('%08x ', ptxt)

          if x > 0x1f and x < 0x7f then
            message=message..string.char(x)
          else
            message=message..'.'
          end
        end
    end

    subtree=tree:add(xor_proto, tvb(), "XOR64 Data")
    subtree:add(tvb(0,4), "XOR64 Key: "..string.format('%08x',key))
    subtree=subtree:add(tvb(4), "XOR64 Cipher Text")
    subtree:add(tvb(4), "XOR64 Plain Text (ascii): "..message)
    subtree:add(tvb(4), "XOR64 Plain Text (hex): "..hexdump)
--    subtree:add(tvb(4), "debug payload length: "..tvb(4):len())
--    subtree:add(tvb(4), "debug decrypted length: "..string.len(message))
  end
end

prot_table = DissectorTable.get("tcp.port")
prot_table:add(443,xor_proto)
