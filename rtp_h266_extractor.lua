--[[
 * rtp_h266_extractor.lua
 * wireshark plugin to extract h266 stream from RTP packets
 * 
 * Copyright (C) 2015 Volvet Zhang <volvet2002@gmail.com>
 *
 * rtp_h266_extractor is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * rtp_h266_extractor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *]]

-- Lua Extractor for rtp h266
-- Author: mobinsheng
--
-- 参考了： https://github.com/volvet/h264extractor
--
-- 用法:
-- 1) 确保Wireshark自带了Lua - "About Wireshark" should say it is compiled with Lua
-- 2) 让Wireshark加载插件，有两种方式：
--   2.1) 放到标准的目录plugins下，例如/path/Wireshark/plugins（macos可能是/path/Wireshark/plugins/wireshark）, Wireshark会自动加载
--   2.2) 把插件放到任意目录，但是需要在init.lua文件的最后加上这句：dofile("/path/rtp_h266.lua")
-- 3) 打开"编辑-->首选项", 在 "Protocols" 下面, 选择H266，然后设置它的payload type，例如99
-- 4) 抓包
-- 5) 把UDP解析为RTP
-- 6) 使用"h266"或者"rtp.p_type == 99"进行过滤
-- 7) 点击"Tool->Video->Export H266" 即可进行h266的dump

do
    local MAX_JITTER_SIZE = 50
    local h266_data = Field.new("h266")
    local rtp_seq = Field.new("rtp.seq")

    -- H266 nalu 头部长度
    local NAL_HDR_SIZE = 2
    -- fu 头部长度
    local FU_HDR_SIZE = 1

    -- 起始码
    local start_code = "\00\00\00\01"

    -- H266 nalu类型
	local H266_NALU_TYPE = {
		TRAIL = 0,
		STSA = 1,
		RADL = 2,
		RASL = 3,
		RSV_VCL_4 = 4,
		RSV_VCL_5 = 5,
		RSV_VCL_6 = 6,
		IDR_W_RADL = 7, -- 关键帧
		IDR_N_LP = 8,  -- 关键帧
		CRA = 9,
		GDR = 10,
		RSV_IRAP_11 = 11,
		OPI = 12,
		DCI = 13,
		VPS = 14,
		SPS = 15,
		PPS = 16,
		PREFIX_APS = 17,
		SUFFIX_APS = 18,
		PH = 19,
		AUD = 20,
		EOS = 21,
		EOB = 22,
		PREFIX_SEI = 23,
		SUFFIX_SEI = 24,
		FD = 25,
		RSV_NVCL_26 = 26,
		RSV_NVCL_27 = 27,
		AP = 28,
		FU = 29,
		--UNSPEC_28 = 28,
		--UNSPEC_29 = 29,
		UNSPEC_30 = 30,
		UNSPEC_31 = 31,
		INVALID = 32,
	}

    -- 获取nalu的名字
	local function get_h266_nalu_name(nalu_type)
		local name = ""
		
		if nalu_type == -1 then
			name = "invalid" -- invalid
		elseif nalu_type == H266_NALU_TYPE.TRAIL then
			name = "DeltaFrame(TRAIL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.STSA then
			name = "DeltaFrame(STSA)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RADL then
			name = "DeltaFrame(RADL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RASL then
			name = "DeltaFrame(RASL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_4 then
			name = "RSV_VCL_4" 
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_5 then
			name = "RSV_VCL_5" 
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_6 then
			name = "RSV_VCL_6" 
		elseif nalu_type == H266_NALU_TYPE.IDR_W_RADL then
			name = "KeyFrame(IDR_W_RADL)"
		elseif nalu_type == H266_NALU_TYPE.IDR_N_LP then
			name = "KeyFrame(IDR_N_LP)"
		elseif nalu_type == H266_NALU_TYPE.CRA then
			name = "DeltaFrame(CRA)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.GDR then
			name = "DeltaFrame(GDR)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RSV_IRAP_11 then
			name = "RSV_IRAP_11"
		elseif nalu_type == H266_NALU_TYPE.OPI then
			name = "OPI"
		elseif nalu_type == H266_NALU_TYPE.DCI then
			name = "DCI"
		elseif nalu_type == H266_NALU_TYPE.VPS then
			name = "VPS"
		elseif nalu_type == H266_NALU_TYPE.SPS then
			name = "SPS"
		elseif nalu_type == H266_NALU_TYPE.PPS then
			name = "PPS"
		elseif nalu_type == H266_NALU_TYPE.PREFIX_APS then
			name = "APS(PREFIX)"
		elseif nalu_type == H266_NALU_TYPE.SUFFIX_APS then
			name = "APS(SUFFIX)"
		elseif nalu_type == H266_NALU_TYPE.PH then
			name = "PH"
		elseif nalu_type == H266_NALU_TYPE.AUD then
			name = "AUD"
		elseif nalu_type == H266_NALU_TYPE.EOS then
			name = "EOS"
		elseif nalu_type == H266_NALU_TYPE.EOB then
			name = "EOB"
		elseif nalu_type == H266_NALU_TYPE.PREFIX_SEI then
			name = "SEI(PREFIX)"
		elseif nalu_type == H266_NALU_TYPE.SUFFIX_SEI then
			name = "SEI(SUFFIX)"
		elseif nalu_type == H266_NALU_TYPE.FD then
			name = "FD"
		elseif nalu_type == H266_NALU_TYPE.RSV_NVCL_26 then
			name = "RSV_NVCL_26"
		elseif nalu_type == H266_NALU_TYPE.RSV_NVCL_27 then
			name = "RSV_NVCL_27"
		elseif nalu_type == H266_NALU_TYPE.AP then
			name = "AP" -- 28
		elseif nalu_type == H266_NALU_TYPE.FU then
			name = "FU" -- 29
		elseif nalu_type == H266_NALU_TYPE.UNSPEC_30 then
			name = "UNSPEC_30"
		elseif nalu_type == H266_NALU_TYPE.UNSPEC_31 then
			name = "UNSPEC_31"
		else
			name = "other"
		end
		
		return name
	end
	
    local function extract_h266_from_rtp()
        local function dump_filter(fd)
            local fh = "h266";
            if fd ~= nil and fd ~= "" then
                return string.format("%s and (%s)", fh, fd)
            else    
                return fh
            end
        end

        local h266_tap = Listener.new("ip", dump_filter(get_filter()))
        local text_window = TextWindow.new("h266 extractor")
        local filename = ""
        local seq_payload_table = { }
        local pass = 0
        local packet_count = 0
        local max_packet_count = 0
        local fu_info = nil
        local pre_seq = 0;
		
        local function log(info)
            text_window:append(info)
            text_window:append("\n")
        end
        
        -- get_preference is only available since 3.5.0
        if get_preference then
            filename = get_preference("gui.fileopen.dir") .. "/" .. os.date("video_%Y%m%d-%H%M%S.266")
        else
            filename = "dump.266"
        end
        
        log("Dumping H266 stream to " .. filename)
        local fp = io.open(filename, "wb")
        if fp == nil then 
            log("open dump file fail")
            return
        end
        
		-- 序号比较
        local function seq_compare(left, right)  
            if math.abs(right.key - left.key) < 1000 then  
                return left.key < right.key  
            else 
                return left.key > right.key  
            end  
        end  
        
		-- 保存single packet
        local function dump_single_nal(h266_payload)
			-- 写入startcode
            fp:write(start_code)
			-- 把整个包保存下来
            fp:write(h266_payload:tvb()():raw())
            fp:flush()
        end
        
		-- 保存fu-a包
        local function dump_fu_a(fu_info) 
            if  fu_info.complete ==  true then 
				-- 写入startcode
                fp:write(start_code)
				-- 写入nalu header
                --fp:write(string.char(fu_info.nal_header))
                fp:write(string.char(fu_info.nal_header_0, fu_info.nal_header_1))

                for i, obj in ipairs(fu_info.payloads) do
                    fp:write(obj:tvb()():raw(NAL_HDR_SIZE + FU_HDR_SIZE)) -- 在264中，它是2因为264的nalu header + fu header一共两个字节
                end
                fp:flush()
            else
                log("ERROR: Incomplete NAL from FUs, dropped")
            end
        end
        
        local function handle_fu_a(seq, h266_data)
			--[[
            H266 nalu头部格式
			+---------------+---------------+
			|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|F|Z| LayerID   |  Type   | TID |
			+---------------+---------------+
			
            H266 fu头格式
			+---------------+
			|0|1|2|3|4|5|6|7|
			+-+-+-+-+-+-+-+-+
			|S|E|P|  FuType |
			+---------------+
			]]--
			
            local fu_header = h266_data:get_index(NAL_HDR_SIZE)
			
			local naltype = bit.band(fu_header, 0x1F)

            -- nalu头的第一个字节
			local nalu_hdr_0 = h266_data:get_index(0)
			-- nalu头的第二个字节
            local nalu_hdr_1 = bit.bor(bit.band(h266_data:get_index(1), 0x07), bit.lshift(naltype, 3))
            
            log("" .. get_h266_nalu_name(naltype) .. " seq = "..tostring(seq))

            if bit.band(fu_header, 0x80) ~= 0 then
                -- fu start flag found
                fu_info = { }
                fu_info.payloads = { }
                fu_info.seq = seq
                fu_info.complete = true
                fu_info.nal_header_0 = nalu_hdr_0
                fu_info.nal_header_1 = nalu_hdr_1
                
                table.insert(fu_info.payloads, h266_data)
                return
            end
            
            if fu_info == nil then 
                log("ERROR: Incomplete FU found: No start flag, dropped")
                return
            end
            
            if seq ~= (fu_info.seq + 1)% 65536 then
                log("ERROR: Incomplete FU found:  fu_info.seq = "..tostring(fu_info.seq)..", input seq = "..tostring(seq))
                fu_info.complete = false;
                return
            end
            
            fu_info.seq = seq
            
            table.insert(fu_info.payloads, h266_data)
            
            if bit.band(fu_header, 0x40) ~= 0 then
                -- fu end flag found

                dump_fu_a(fu_info)

                fu_info = nil
            end 
            
        end
        
        local function handle_stap_a(seq, h266_data)
            offset = NAL_HDR_SIZE		--h264的时候是1 -- skip nal header of STAP-A
            repeat
                size = h266_data:tvb()(offset, 2):uint()
                offset = offset + 2
                local next_nal_type = bit.band(h266_data:get_index(offset), 0x1f)

                log("" .. get_h266_nalu_name(next_nal_type) .. " seq = "..tostring(seq))

                fp:write(start_code)
                fp:write(h266_data:tvb()():raw(offset, size))

                offset = offset + size
            until offset >= h266_data:tvb():len()
            fp:flush()
        end

        local function on_ordered_h266_payload(seq, h266_data)
            -- 获取nalu 类型
			local naltype = bit.band(bit.rshift(h266_data:get_index(1), 3), 0x1f)

            -- 单包：single packet
            if naltype < 28 then 
                -- Single NAL unit packet
                if fu_info ~= nil then
                    log("ERROR: Incomplete FU found: No start flag, dropped")
                    fu_info = nil
                end

                log("" .. get_h266_nalu_name(naltype) .. " seq = "..tostring(seq))

                dump_single_nal(h266_data)
				
            -- 分片包：Fu packet
            elseif naltype == 29 then
                -- FU-A
                handle_fu_a(seq, h266_data)

            -- 聚合包：AP
            elseif naltype == 28 then
                -- STAP-A
                if fu_info ~= nil then
                    log("ERROR: Incomplete FU found: No start flag, dropped")
                    fu_info = nil
                end
                handle_stap_a(seq, h266_data)
            else
                log("ERROR: tap.packet: "..", Unsupported nal, naltype = "..tostring(naltype))				
            end 
        end
        
        local function on_jitter_buffer_output()
            -- 序号排序
            table.sort(seq_payload_table, seq_compare)
            
            if #seq_payload_table > 0 then
                on_ordered_h266_payload(seq_payload_table[1].key, seq_payload_table[1].value)
                table.remove(seq_payload_table, 1)
            end
        end
        
        local function jitter_buffer_finilize() 
            for i, obj in ipairs(seq_payload_table) do
                on_ordered_h266_payload(obj.key, obj.value)
            end
        end
        
        -- 处理rtp中的h266 payload
        local function on_h266_rtp_payload(seq, payload)
            local cur_seq = seq.value
            
			if packet_count == 0 then
                pre_seq = cur_seq
            else
                if cur_seq == pre_seq then
                    -- 重复包
                    packet_count = packet_count + 1
                    --log("WARN: duplicate seq = "..tostring(seq.value)..",packet_count = "..packet_count)
                    return
                else
                    pre_seq = cur_seq
                end
            end

            packet_count = packet_count + 1

            -- 缓存
            table.insert(seq_payload_table, { key = tonumber(seq.value), value = payload.value })
            
            --log("on_h266_rtp_payload: table size is "..tostring(#seq_payload_table))
            -- jitter buffer满了，然后开始处理buffer里的所有数据
            if #seq_payload_table > MAX_JITTER_SIZE then
                on_jitter_buffer_output()
            end
        end
        
        function h266_tap.packet(pinfo, tvb)
            local payloadTable = { h266_data() }
            local seqTable = { rtp_seq() }
            
            if (#payloadTable) < (#seqTable) then 
                log("ERROR: payloadTable size is "..tostring(#payloadTable)..", seqTable size is "..tostring(#seqTable))
                return
            end
            
            if pass == 0 then 
                for i, payload in ipairs(payloadTable) do
                    max_packet_count = max_packet_count + 1
                end
            else 
                
                for i, payload in ipairs(payloadTable) do
                    on_h266_rtp_payload(seqTable[1], payload)
                end
                
                if packet_count == max_packet_count then
                    jitter_buffer_finilize()
                end
            end 
        end
		
        function h266_tap.reset()
        end
		
        function h266_tap.draw() 
        end
		
        local function remove() 
            if fp then 
                fp:close()
                fp = nil
            end
            h266_tap:remove()
        end 
		
        log("Start")
		
        text_window:set_atclose(remove)
	
        log("phase 1")
        pass = 0
        retap_packets() -- 自动调用h266_tap.packet
        
        log("phase 2:  max_packet_count = "..tostring(max_packet_count))
        pass = 1

        retap_packets() -- 自动调用h266_tap.packet

        if fp ~= nil then 
           fp:close()
           fp = nil
           log("Video stream written to " .. filename)
        end
        
        log("End")
	end

    -- 注册到UI菜单中
    register_menu("Video/Export H266", extract_h266_from_rtp, MENU_TOOLS_UNSORTED)
	--register_menu("Extract h266 stream from RTP", extract_h266_from_rtp, MENU_TOOLS_UNSORTED)
end
