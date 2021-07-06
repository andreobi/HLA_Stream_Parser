# High Level Analyzer - Stream Parser
# For more information and documentation, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions
# The software is provided as it is without any liability and without any warranty.
# The author will take no responsibility.

# A stream packet can contain the following parts:
#   - Time to Packet: before a new packet start, it looks for an idle time in ms, max=1s
#   - Preamble      : number of unchecked bytes
#   - Header        : 0-8 bytes, no need to insert ending '0'; left aligned like the incoming stream
#   - Header Pad    : number of unchecked bytes
#   - Length        : 0-2 bytes to specify the packet length
#   - Length Pad    : number of unchecked bytes
#   - DATA          : number = packet length - options
#   - Data Pad      : number of unchecked bytes (is not part of crc)
#   - Crc           : 0-4 bytes crc checksum
#   - Crc Pad       : number of unchecked bytes to reach packet end
#   - Packed Pad    : the left over if a fixed packed length is behind Crc Pad (packet_fix_length - length)
#
#   - Header Mask   : Stream bytes and mask == Header and mask? if mask==0 => everything is a match
#   - Tigger Mask   : is operated to the stream header if the
#   - Tigger Value  : Header and Trigger Mask == Trigger Value and Trigger Mask => Trigger set
#   - Trigger Time Max  : if Trigger Set: Trigger Time starts at packet end => True next frame before Tmax
#   - Packet timeout    : resets the current parsing in ms
#   - Packet fix length : specifies the total packet length
#   - Length fix        : if Length == 0 => specifies the length for data and crc
#   - Length Offset     : can be used to adjust the data length

#  flex search means the header length is determent by the header value input, inputs can have different lengths
#   - Time_to_Packet == 0, Header_length == 0,  => Packet starts after flex Header match
#   - Time_to_Packet == 0, Header_length >  0,  => Packet starts after fix Header length match
#   - Time_to_Packet >  0, Header_length == 0,  => Packet starts after Time to Header (Idle)
#   - Time_to_Packet >  0, Header_length >  0,  => Packet starts after Idle and fix Header length match

#   - Time_to_Packet == 0, Header_length == 0,  Header_value      => Packet starts after Idle
#   - a double P-End indicates that the packet length is shorter than the packet definition

# there are almost no plausibility check => define '....' and you get something

# open topics
# - crc implementation: please implement it according to your own needs
#       there will be no update on this topic
# - error handling e.g. Stream error
#       so fare there was no need to handle errors
#       nothing planed on this topic

# topics that could be improved
# - output after timeout and potential header


from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data.timing import GraphTime, GraphTimeDelta


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    packet_fix_length = NumberSetting(min_value=0, max_value=65535)
    packet_starttime = NumberSetting(min_value=0, max_value=999.999)
    packet_timeout = NumberSetting(min_value=0, max_value=999.999)
    #
    preamble_length = NumberSetting(min_value=0, max_value=65535)
    #
    header_length = NumberSetting(min_value=0, max_value=8)
    header_mask_low = StringSetting()
    header_mask_high = StringSetting()
    header_0_active = ChoicesSetting(choices=('ON', 'OFF'))
    header_0_value_low = StringSetting()
    header_0_value_high = StringSetting()
    header_1_active = ChoicesSetting(choices=('ON', 'OFF'))
    header_1_value_low = StringSetting()
    header_1_value_high = StringSetting()
    header_2_active = ChoicesSetting(choices=('ON', 'OFF'))
    header_2_value_low = StringSetting()
    header_2_value_high = StringSetting()
    header_3_active = ChoicesSetting(choices=('ON', 'OFF'))
    header_3_value_low = StringSetting()
    header_3_value_high = StringSetting()
    header_pad_length = NumberSetting(min_value=0, max_value=65535)
    #
    length_cnt_start = ChoicesSetting(choices=('preamble', 'header', 'header pad', 'length', 'length pad', 'data'))
    length_fix = NumberSetting(min_value=0, max_value=65535)  # 0 => length from stream
    length_offset = NumberSetting(min_value=-16384, max_value=16384)  # to adopt the length counting: i.e start =1
    length_length = NumberSetting(min_value=0, max_value=2)
    length_order = ChoicesSetting(choices=('01', '10'))  # stream byte order
    length_mask = StringSetting()  # takes only 1 bits as length
    length_pad_length = NumberSetting(min_value=0, max_value=65535)
    #
    data_pad_length = NumberSetting(min_value=0, max_value=65535)
    #
    crc_polynomial = StringSetting()
    crc_start_value = StringSetting()
    crc_finalize_value = StringSetting()
    crc_mirror_inputs = ChoicesSetting(choices=('ON', 'OFF'))
    crc_mirror_results = ChoicesSetting(choices=('ON', 'OFF'))
    crc_type = ChoicesSetting(choices=('8', '16', '32'))
    crc_cnt_start = ChoicesSetting(
        choices=('NO_CRC', 'preamble', 'header', 'header pad', 'length', 'length pad', 'data'))
    crc_length = NumberSetting(min_value=0, max_value=4)
    crc_order = ChoicesSetting(choices=('0123', '1032', '2301', '3210'))  # stream byte order
    crc_pad_length = NumberSetting(min_value=0, max_value=65535)
    # crc init, end, polynomial
    #
    trigger_value_high = StringSetting()
    trigger_value_low = StringSetting()
    trigger_mask_high = StringSetting()
    trigger_mask_low = StringSetting()
    trigger_tmax = NumberSetting(min_value=0, max_value=999.999)
    #
    # the different packet information
    result_types = {
        'streamstart': {'format': 'STREAM'},
        'timetoheader': {'format': 'TtH: {{data.data}}'},
        'preamble': {'format': 'p: {{data.data}}'},
        'header': {'format': 'H: {{data.data}}'},
        'headerqm': {'format': 'H?: {{data.data}}'},
        'headerpad': {'format': 'hp: {{data.data}}'},
        'length': {'format': 'L: {{data.data}}'},
        'lengthpad': {'format': 'lp: {{data.data}}'},
        'data': {'format': 'D: {{data.data}}'},
        'datapad': {'format': 'dp: {{data.data}}'},
        'crcadd': {'format': 'C({{data.data}})'},
        'crcvalue': {'format': 'CV: {{data.data}}'},
        'crcend': {'format': 'CRC: {{data.stat}}, S: {{data.sum}}, V: {{data.value}}'},
        'crcpad': {'format': 'cp: {{data.data}}'},
        'packetpad': {'format': 'pp:  {{data.data}}'},
        'packetstart': {'format': 'P-START'},
        'packetend': {'format': 'P-END'},
        'packettimeout': {'format': 'P-T_OUT:   {{data.data}}'},
        'triggerfound': {'format': 'TRIG'},
        'triggerstream': {'format': 'Trig: {{data.data}}'},
        # not used so far
        'error': {'format': 'Output type: {{type}}, Input type: {{data.input_type}}'}
    }

    # converts a string into a 4 byte list, no leading '0' required
    def convert_hexstr_to_bytes(in_str, valueName=''):
        result = [0] * 4
        in_byte = bytes(in_str, 'ascii')
        in_len_max = len(in_str)
        if in_len_max > 8:
            in_len_max = 8
        for nibble_pos in range(0, in_len_max):
            value = in_byte[nibble_pos]
            if (value >= 0x30) and (value <= 0x39):
                value -= 0x30
            elif (value >= 0x41) and (value <= 0x46):
                value -= 0x37
            elif (value >= 0x61) and (value <= 0x66):
                value -= 0x57
            else:
                value = 0
                raise Exception('Hex Error', valueName)
            if nibble_pos % 2 == 0:
                value *= 16
            result[nibble_pos // 2] += value
        return result

    # squeeze output to one frame
    def squeeze_frame(self, output):
        if len(output) > 1:
            field_dtime = (output[0].end_time - output[0].start_time) / len(output)
            field_start_t = output[0].start_time
            for x in output:
                x.start_time = field_start_t
                field_start_t += field_dtime
                x.end_time = field_start_t
        return output

    # state machine initialization
    def state_init(self):
        self.flag_timeout = False
        self.flag_time_to_head = False
        self.flag_header = False
        self.flag_header_match = [True] * 4
        self.flag_length = False
        self.flag_end = False
        self.state = 1
        self.state_ref_pos = 0
        self.packet_pos = 0
        self.packet_length = int(0)
        self.length_bytes = [0] * 2
        self.crc_flag_init = False
        self.crc_flag_okay = False
        self.crc_flag_add = False
        self.crc_flag_done = False
        self.crc_flag_checked = False
        self.crc_value = 0

    # stream start
    def s0(self):
        # print('s0 Stream start', self.frame.start_time)
        self.state_init()
        self.packet_pos = 1
        self.return_value.append(AnalyzerFrame('streamstart', self.frame.start_time, self.frame.end_time, {}))
        self.state_func[self.state]()

    # time to start
    def s1(self):
        if self.packetstarttime <= self.delta_time:
            # print('s1')
            self.flag_time_to_head = True
            self.state += 1
            self.state_ref_pos += self.preamble_length
            if self.packetstarttime > 0:
                self.return_value.append(AnalyzerFrame('timetoheader', self.frame.start_time, self.frame.end_time,
                                                       {'data': self.delta_time * 1000}))
            self.state_func[self.state]()
        else:
            self.state_init()

    # preamble, makes only sense when time to header is used
    def s2(self):
        if self.packet_pos > self.state_ref_pos:
            self.flag_trigger_search = True
            self.flag_trigger_found = False
            self.flag_trigger_pend = False
            self.state += 1
            self.state_ref_pos += self.header_length
            self.state_func[self.state]()
        else:
            # print('S2')
            self.return_value.append(AnalyzerFrame('preamble', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # flexible header search init
    def header_parser_init(self):
        for ibp in range(0, len(self.inBuffer_tout)):
            self.inBuffer_tout[ibp] = True

    # flexible header search max 8 chr see __init__ and header value
    def header_parser(self, data):
        ibl = len(self.inBuffer)
        for ibp in range(1, ibl):
            self.inBuffer[ibp - 1] = self.inBuffer[ibp]
            self.inBuffer_tout[ibp - 1] = self.inBuffer_tout[ibp]
        self.inBuffer[ibl - 1] = data
        self.inBuffer_tout[ibl - 1] = self.flag_timeout
        self.inBuffer_tout[ibl - 2] = self.flag_timeout  # because timeout belongs to the previous frame

        for header_pos in range(0, self.header_num):
            if not self.header_active[header_pos]:
                continue
            head = self.header_data[header_pos]
            buff_pos = ibl - len(head)
            for data_pos in range(0, len(head)):
                if self.inBuffer_tout[buff_pos]:
                    break
                if self.inBuffer[buff_pos] == head[data_pos]:
                    if buff_pos == ibl - 1:
                        buff_pos = ibl - len(head)
                        self.flag_trigger_search = True
                        for t_pos in range(0, len(head)):  # check for trigger mask
                            if int(self.inBuffer[buff_pos]) & self.triggerMask[t_pos] != \
                                    self.triggerValue[t_pos] & self.triggerMask[t_pos]:
                                self.flag_trigger_search = False
                            buff_pos += 1
                        return header_pos, data_pos  # string match
                else:
                    break
                buff_pos += 1
        return -1, 0  # no complete or no match

    # header
    def s3(self):
        if self.packetstarttime:
            if self.header_length > 0:  # fixed header length => linear search with preamble
                # print('S3 tth')
                header_pos = int(self.packet_pos - self.state_ref_pos + self.header_length - 1)
                # check for trigger mask
                if self.frame.data['data'][self.data_pos] & self.triggerMask[header_pos] != \
                        self.triggerValue[header_pos] & self.triggerMask[header_pos]:
                    self.flag_trigger_search = False
                # check for header
                frame_dat = self.frame.data['data'][self.data_pos] & self.headerMask[header_pos]
                no_match = 0
                for i in range(0, 4):
                    if frame_dat != self.header_data[i][header_pos] or not len(self.header_data[i]) \
                            or not self.header_active[i]:
                        self.flag_header_match[i] = False
                        no_match += 1
                if no_match == 4:
                    self.state_init()
                    return
                self.return_value.append(AnalyzerFrame('header', self.frame.start_time, self.frame.end_time, {
                    'data': frame_dat.to_bytes(1, 'big')}))

            # packet start only based on time and/or header found
            if self.packet_pos >= self.state_ref_pos:
                if self.flag_header_match[0] or self.flag_header_match[1] or self.flag_header_match[2] or \
                        self.flag_header_match[3]:
                    self.return_value.append(
                        AnalyzerFrame('packetstart', self.frame.start_time, self.frame.end_time, {}))
                    if self.flag_trigger_search:
                        self.return_value.append(
                            AnalyzerFrame('triggerfound', self.frame.start_time, self.frame.end_time, {}))
                        self.flag_trigger_found = True
                    self.flag_trigger_search = False
                    self.flag_header = True
                    self.state += 1
                    self.state_ref_pos += self.header_pad_length
                    if self.header_length == 0 and self.packetstarttime > 0:
                        self.state_func[self.state]()
                else:
                    self.state_init()
                    return

        else:  # no time trigger; flexible or fix header length only
            # print('S3 flex')
            hp, dp = self.header_parser(self.frame.data['data'][self.data_pos])
            if hp != -1:  # header found
                self.flag_header = True
                self.state += 1
                self.return_value.append(AnalyzerFrame('header', self.frame.start_time, self.frame.end_time, {
                    'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))
                self.return_value.append(AnalyzerFrame('packetstart', self.frame.start_time, self.frame.end_time, {}))
                if self.flag_trigger_search:
                    self.return_value.append(
                        AnalyzerFrame('triggerfound', self.frame.start_time, self.frame.end_time, {}))
                    self.flag_trigger_found = True
                self.flag_trigger_search = False
                self.packet_pos = dp + 1
                self.state_ref_pos = dp + 1 + self.header_pad_length
                # cleanup buffer:delete everything before the header
                del_buf_pos = 0
                while len(self.output_buf_opt) > dp + del_buf_pos:
                    if len(self.output_buf_force) < del_buf_pos + 1 or len(self.output_buf_opt) < del_buf_pos + 1:
                        break
                    if self.output_buf_force[del_buf_pos]:
                        del_buf_pos += 1
                    else:
                        if self.output_buf_opt[del_buf_pos]:
                            self.output_buf_opt.pop(del_buf_pos)
            else:
                del_buf_pos = 0
                if self.flag_timeout:
                    del_buf_depth = 0
                    self.return_value.append(AnalyzerFrame('headerqm', self.frame.start_time, self.frame.end_time, {
                        'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))
                else:
                    del_buf_depth = 8
                    self.return_value.append(AnalyzerFrame('header', self.frame.start_time, self.frame.end_time, {
                        'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))
                # cleanup buffer: delete everything before buffer depth
                while len(self.output_buf_opt) + del_buf_pos > del_buf_depth:
                    if len(self.output_buf_force) < del_buf_pos + 1 or len(self.output_buf_opt) < del_buf_pos + 1:
                        break
                    if self.output_buf_force[del_buf_pos]:
                        del_buf_pos += 1
                    else:
                        if self.output_buf_opt[del_buf_pos]:
                            self.output_buf_opt.pop(del_buf_pos)

    # header pad
    def s4(self):
        if self.packet_pos > self.state_ref_pos:
            self.state += 1
            self.state_ref_pos += self.length_length
            self.state_func[self.state]()
        else:
            # print('S4')
            self.return_value.append(AnalyzerFrame('headerpad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # length
    def s5(self):
        if self.packet_pos > self.state_ref_pos:
            if self.length_length == 0:
                self.packet_length = int(self.length_fix)
            elif self.length_length == 1:
                self.packet_length = int(self.length_bytes[0])
            else:  # multiply high byte according to low and high mask
                pos_h = int(self.length_order[0])
                pos_l = int(self.length_order[1])
                length_dat = self.length_bytes[pos_h]
                for b in f'{self.length_mask_bytes[pos_l]:08b}':
                    if b == '0':
                        length_dat <<= 1
                self.packet_length = int(length_dat | self.length_bytes[pos_l])
            # add offset and limit to 0
            self.packet_length += self.length_offset
            self.return_value.append(AnalyzerFrame('length', self.frame.start_time, self.frame.end_time, {
                'data': self.packet_length}))
            self.packet_length += self.packet_length_shift
            if self.packet_length < 0:
                self.packet_length = 0
            self.flag_length = True
            self.state += 1
            self.state_ref_pos += self.length_pad_length
            self.state_func[self.state]()
        else:
            # print('S5')
            length_pos = int(self.packet_pos - self.state_ref_pos + self.length_length - 1)
            length_dat = self.frame.data['data'][self.data_pos] & self.length_mask_bytes[length_pos]
            for b in bin(self.length_mask_bytes[length_pos])[2:]:
                if b == '0':
                    length_dat >>= 1
            self.length_bytes[length_pos] = length_dat
            self.return_value.append(AnalyzerFrame('length', self.frame.start_time, self.frame.end_time,
                                                   {'data': length_dat.to_bytes(1, 'big')}))

    # length pad
    def s6(self):
        if self.packet_pos > self.state_ref_pos:
            self.state += 1
            self.state_ref_pos = self.packet_length - self.data_pad_length - self.crc_length - self.crc_pad_length
            self.state_func[self.state]()
        else:
            # print('S6')
            self.return_value.append(AnalyzerFrame('lengthpad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # data
    def s7(self):
        if self.packet_pos > self.state_ref_pos:
            self.crc_flag_add = False
            self.state += 1
            self.state_ref_pos += self.data_pad_length
            self.state_func[self.state]()
        else:
            # print('S7')
            self.return_value.append(AnalyzerFrame('data', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # data pad
    def s8(self):
        if self.packet_pos > self.state_ref_pos:
            self.state += 1
            self.state_ref_pos += self.crc_length
            self.state_func[self.state]()
        else:
            # print('S8')
            self.return_value.append(AnalyzerFrame('datapad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # crc
    def s9(self):
        if self.packet_pos > self.state_ref_pos:
            self.state_ref_pos += self.crc_pad_length
            self.state += 1
            self.state_func[self.state]()
        else:
            # print('S9')
            crc_pos = int(self.packet_pos - self.state_ref_pos + self.crc_length - 1)
            crc_dat = self.frame.data['data'][self.data_pos]
            self.crc_value += (crc_dat << (int(self.crc_order[crc_pos]) * 8))
            if self.packet_pos >= self.state_ref_pos:
                self.crc_flag_done = True
            self.return_value.append(AnalyzerFrame('crcvalue', self.frame.start_time, self.frame.end_time, {
                'data': crc_dat.to_bytes(1, 'big')}))

    # crc pad
    def s10(self):
        if self.packet_pos > self.state_ref_pos:
            self.state += 1
            self.state_func[self.state]()
        else:
            # print('S10')
            self.return_value.append(AnalyzerFrame('crcpad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))

    # packet pad
    def s11(self):
        if self.packet_fix_length == 0:
            self.state += 1
            self.state_func[self.state]()
        elif self.packet_pos < self.packet_fix_length:
            # print('S11')
            self.return_value.append(AnalyzerFrame('packetpad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))
        elif self.packet_pos == self.packet_fix_length:
            # print('S11')
            self.state += 1
            self.return_value.append(AnalyzerFrame('packetpad', self.frame.start_time, self.frame.end_time, {
                'data': self.frame.data['data'][self.data_pos].to_bytes(1, 'big')}))
        else:
            self.state += 1
            self.state_func[self.state]()

    # packet end
    def s12(self):
        # print('S12')
        self.flag_end = True
        self.flag_trigger_pend = True
        self.trigger_start_time = self.frame.end_time
        self.return_value.append(AnalyzerFrame('packetend', self.frame.start_time, self.frame.end_time, {}))

    # check for packet end after each frame
    def s_end(self):
        if self.flag_length:
            if self.packet_fix_length == 0:
                if self.packet_pos >= self.packet_length:
                    self.state_func[12]()
            else:
                if self.packet_pos >= self.packet_length and self.packet_pos >= self.packet_fix_length:
                    self.state_func[12]()

    def __init__(self):
        self.header_num = 4  # number of headers
        self.inBuffer = ['0'] * 8  # buffer depth >= len(header)
        self.inBuffer_tout = [True] * 8  # after startup: buffer is not valid (Timeout)

        self.state = 0
        self.state_func = (self.s0, self.s1, self.s2, self.s3, self.s4, self.s5, self.s6, self.s7, self.s8, self.s9,
                           self.s10, self.s11, self.s12)
        self.flag_time_to_head = False
        self.flag_header = False
        self.flag_header_match = [True] * 4
        self.flag_length = False
        self.flag_end = False
        self.flag_force_output = False
        self.output_buf_opt = []
        self.output_buf_force = []
        self.return_frame = []
        #
        self.state_ref_pos = 0
        self.data_pos = 0
        #
        self.frame: AnalyzerFrame = None
        self.lastframe: AnalyzerFrame = None
        self.delta_time = 0
        #
        self.triggerTmax = GraphTimeDelta(0)

        h_data = [self.header_0_value_high, self.header_1_value_high, self.header_2_value_high,
                  self.header_3_value_high]
        l_data = [self.header_0_value_low, self.header_1_value_low, self.header_2_value_low, self.header_3_value_low]

        self.headerMask = Hla.convert_hexstr_to_bytes(self.header_mask_high, 'header mask')
        self.headerMask += Hla.convert_hexstr_to_bytes(self.header_mask_low, 'header mask')
        hm_default = True
        for hm in self.headerMask:
            if hm:
                hm_default = False
        if hm_default:
            self.headerMask = [255] * 8
        self.header_data = [[0] * 8] * 4
        for i in range(0, 4):
            self.header_data[i] = Hla.convert_hexstr_to_bytes(h_data[i], 'header hx value')
            self.header_data[i] += Hla.convert_hexstr_to_bytes(l_data[i], 'header lx value')
            if self.header_length == 0 and self.packet_starttime == 0:
                if len(h_data[i]) == 8:
                    hl = 4 + len(l_data[i]) // 2
                else:
                    hl = len(h_data[i]) // 2
                while len(self.header_data[i]) > hl:
                    self.header_data[i].pop()
            else:
                while len(self.header_data[i]) > self.header_length:
                    self.header_data[i].pop()
            for j in range(0, len(self.header_data[i])):
                self.header_data[i][j] &= self.headerMask[j]

        self.header_active = [False] * 4
        if self.header_0_active == 'ON':
            self.header_active[0] = True
        if self.header_1_active == 'ON':
            self.header_active[1] = True
        if self.header_2_active == 'ON':
            self.header_active[2] = True
        if self.header_3_active == 'ON':
            self.header_active[3] = True
        self.triggerValue = Hla.convert_hexstr_to_bytes(self.trigger_value_high, 'trigger value')
        self.triggerValue += Hla.convert_hexstr_to_bytes(self.trigger_value_low, 'trigger value')
        self.triggerMask = Hla.convert_hexstr_to_bytes(self.trigger_mask_high, 'trigger mask')
        self.triggerMask += Hla.convert_hexstr_to_bytes(self.trigger_mask_low, 'trigger mask')
        tm_default = True
        for tm in self.triggerMask:
            if tm:
                tm_default = False
        if tm_default:
            self.triggerMask = self.triggerValue

        self.triggerTmax = self.trigger_tmax / 1000
        self.trigger_start_time = GraphTimeDelta(0)
        self.flag_trigger_found = False
        self.flag_trigger_search = False
        self.flag_trigger_pend = False

        self.packetstarttime = self.packet_starttime / 1000
        self.packettimeout = self.packet_timeout / 1000
        self.flag_timeout = False
        self.packet_pos = 0
        self.packet_length: int = 0
        self.length_bytes = [0] * 2
        self.length_mask_bytes = Hla.convert_hexstr_to_bytes(self.length_mask)
        self.return_value: AnalyzerFrame = []
        self.output_force: AnalyzerFrame = []
        self.packet_length_shift = 0
        if self.length_cnt_start == 'header':
            self.packet_length_shift = self.preamble_length
        elif self.length_cnt_start == 'header pad':
            self.packet_length_shift = self.preamble_length + self.header_length
        elif self.length_cnt_start == 'length':
            self.packet_length_shift = self.preamble_length + self.header_length + self.header_pad_length
        elif self.length_cnt_start == 'length pad':
            self.packet_length_shift = self.preamble_length + self.header_length + self.header_pad_length + self.length_length
        elif self.length_cnt_start == 'data':
            self.packet_length_shift = self.preamble_length + self.header_length + self.header_pad_length + self.length_length + self.length_pad_length
        #
        # crc helper
        self.crc_mask = {'8': 0x000000ff, '16': 0x0000ffff, '32': 0xffffffff}
        self.crc_msb = {'8': 0x00000080, '16': 0x00008000, '32': 0x80000000}
        self.crc_shift = {'8': 0, '16': 8, '32': 24}
        self.crc_poly_lookup = [0] * 256
        self.crc_mbyte_lookup = [0] * 256
        # crc definition
        # self.crc_type = '8'
        self.crc_poly = int.from_bytes(Hla.convert_hexstr_to_bytes(self.crc_polynomial), 'big')
        self.crc_init = int.from_bytes(Hla.convert_hexstr_to_bytes(self.crc_start_value), 'big')
        self.crc_finalize = int.from_bytes(Hla.convert_hexstr_to_bytes(self.crc_finalize_value), 'big')
        if self.crc_type == '8':
            self.crc_poly >>= 24
            self.crc_init >>= 24
            self.crc_finalize >>= 24
        elif self.crc_type == '16':
            self.crc_poly >>= 16
            self.crc_init >>= 16
            self.crc_finalize >>= 16
        self.crc_mirror_input = False
        if self.crc_mirror_inputs == 'ON':
            self.crc_mirror_input = True
        self.crc_mirror_result = False
        if self.crc_mirror_results == 'ON':
            self.crc_mirror_result = True
        # crc sum
        self.crc_def_sum = 0
        # crc sum after finalize
        self.crc_def_result = 0
        #
        self.crc_def_create_mbyte_table()
        self.crc_def_create_poly_table()
        # crc state
        self.crc_flag_docrc = True
        self.crc_flag_init = False
        self.crc_flag_add = False
        self.crc_flag_done = False
        self.crc_flag_checked = False
        self.crc_flag_okay = False
        # crc info from packet
        self.crc_value = 0
        self.crc_length_shift = 0
        if self.crc_cnt_start == 'header':
            self.crc_length_shift = self.preamble_length
        elif self.crc_cnt_start == 'header pad':
            self.crc_length_shift = self.preamble_length + self.header_length
        elif self.crc_cnt_start == 'length':
            self.crc_length_shift = self.preamble_length + self.header_length + self.header_pad_length
        elif self.crc_cnt_start == 'length pad':
            self.crc_length_shift = self.preamble_length + self.header_length + self.header_pad_length + self.length_length
        elif self.crc_cnt_start == 'data':
            self.crc_length_shift = self.preamble_length + self.header_length + self.header_pad_length + self.length_length + self.length_pad_length
        elif self.crc_cnt_start == 'NO_CRC':
            self.crc_flag_docrc = False
        print()
        print('!--- Config ----------------')
        print('Header mask     :', ''.join(format(x, '02x') for x in self.headerMask))
        for i in range(0, 4):
            print('Header', i, 'value  :', ''.join(format(x, '02x') for x in self.header_data[i]), self.header_active[i])
        print('Trigger mask    :', ''.join(format(x, '02x') for x in self.triggerMask))
        print('Trigger value   :', ''.join(format(x, '02x') for x in self.triggerValue))
        print('Trigger Tmax    :', self.triggerTmax * 1000, '[ms]')
        if self.packet_fix_length > 0:
            print('Packet min len  :', int(self.packet_fix_length))
        if self.length_length == 0:
            print('length total    :', int(self.length_fix + self.packet_length_shift + self.length_offset))
        else:
            print('P-Count start   :', self.length_cnt_start)
            print('length total    :', 'Len(stream) + ', int(self.packet_length_shift + self.length_offset))
            if self.length_length == 1:
                print('Length mask     :', format(self.length_mask_bytes[0], '02x'))
            else:
                print('Length mask     :', format(self.length_mask_bytes[0], '02x'),
                      format(self.length_mask_bytes[1], '02x'))
        print('CRC polynom     :', hex(self.crc_poly))
        print('CRC start v     :', hex(self.crc_init))
        print('CRC finalizer   :', hex(self.crc_finalize))
        print('CRC mirror input:', self.crc_mirror_input, ' result:', self.crc_mirror_result)

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'data':
            self.frame = frame
            # start with a clear frame output
            self.return_value: AnalyzerFrame = []
            self.output_force: AnalyzerFrame = []

            self.flag_force_output = False
            self.flag_timeout = False
            # change this if your stream.data has multiple bytes
            self.data_pos = int(len(self.frame.data['data']) - 1)

            # first run: state == 0
            if self.state:
                self.delta_time = float(self.frame.start_time - self.lastframe.end_time)
                # check for packet timeout
                if 0 < self.packettimeout < self.delta_time:
                    if self.flag_time_to_head:
                        self.flag_force_output = True
                        self.output_force.append(AnalyzerFrame('packettimeout', self.frame.start_time,
                                                               self.frame.end_time, {'data': self.packet_pos}))
                    self.header_parser_init()
                    self.state_init()
                    self.flag_timeout = True
            else:
                self.delta_time = 1  # time is 1s

            # output trigger time only if trigger found and packet finished
            if self.flag_trigger_found and self.flag_trigger_pend:
                self.flag_trigger_found = False
                self.flag_trigger_pend = False
                d_trigger_time = self.frame.start_time - self.trigger_start_time
                if float(d_trigger_time) > self.triggerTmax:
                    td = 'OUT'
                else:
                    td = 'IN'
                self.flag_force_output = True
                self.output_force.append(AnalyzerFrame('triggerstream', self.frame.start_time, self.frame.end_time,
                                                       {'data': td}))
            # count frame and call state machine
            self.packet_pos += 1
            self.state_func[self.state]()

            if self.crc_flag_docrc:
                self.do_crc()

            self.lastframe = frame
            # handle buffer for return content
            if self.flag_force_output or self.flag_time_to_head:  # should return_value be added to the output buffer?
                self.output_buf_opt.append(self.return_value)
                self.output_buf_force.append(self.output_force)

            if self.flag_time_to_head:  # should return value be shown?
                self.s_end()
                if self.flag_header or self.flag_end or self.flag_timeout:
                    output = []
                    for i in range(0, len(self.output_buf_opt)):
                        output += self.squeeze_frame(self.output_buf_force[i] + self.output_buf_opt[i])
                    self.output_buf_force = []
                    self.output_buf_opt = []
                    if self.flag_end:
                        self.state_init()
                        self.header_parser_init()
                    return output
            else:
                if self.flag_force_output:
                    output = []
                    for i in range(0, len(self.output_buf_opt)):
                        output += self.squeeze_frame(self.output_buf_force[i] + self.output_buf_opt[i])
                    self.output_buf_force = []
                    self.output_buf_opt = []
                    if self.flag_end:
                        self.state_init()
                        self.header_parser_init()
                    return output

                self.output_buf_force = []
                self.output_buf_opt = []
        else:
            # print('no data frame')
            nop = 0  # to satisfy ...

    # main call for crc calculation
    def do_crc(self):
        if self.packet_pos > self.crc_length_shift:
            if not self.crc_flag_init:
                self.crc_def_init()

            if self.crc_flag_add:
                data_v = self.frame.data['data'][self.data_pos]
                self.crc_def_add(data_v)
                data_v = data_v.to_bytes(1, 'big')
                self.return_value.append(AnalyzerFrame('crcadd', self.frame.start_time, self.frame.end_time,
                                                       {'data': hex(self.crc_def_result)}))

            if self.crc_flag_done:
                self.crc_def_finalize()
                if self.crc_flag_okay:
                    crc_result = 'OK'
                else:
                    crc_result = 'ER'
                self.return_value.append(AnalyzerFrame('crcend', self.frame.start_time, self.frame.end_time,
                                                       {'stat': crc_result, 'sum': self.crc_def_result.to_bytes(4, 'big'),
                                                        'value': self.crc_value.to_bytes(4, 'big')}))

    #
    def crc_def_init(self):
        self.crc_flag_init = True
        self.crc_flag_add = True
        self.crc_flag_done = False
        self.crc_flag_okay = False
        self.crc_def_sum = self.crc_init

    #
    def crc_def_add(self, value: int):
        if self.crc_mirror_input:
            value = self.crc_mbyte_lookup[value]
        crc_pos = (value ^ (self.crc_def_sum >> self.crc_shift[self.crc_type])) & 0xff
        if self.crc_type == 8:
            self.crc_def_sum = self.crc_poly_lookup[int(crc_pos)]  # 8
        else:
            self.crc_def_sum = ((self.crc_def_sum << 8) ^ self.crc_poly_lookup[int(crc_pos)]) \
                               & self.crc_mask[self.crc_type]  # 16 or 32
        value = self.crc_def_sum
        # do always a final calculation to show intermediate results
        if self.crc_mirror_result:
            if self.crc_type == '8':
                value = self.crc_mbyte_lookup[value]
            elif self.crc_type == '16':
                temp = value
                value = (self.crc_mbyte_lookup[temp & 0xff]) << 8
                value |= self.crc_mbyte_lookup[(temp >> 8) & 0xff]
            else:
                temp = value
                value = (self.crc_mbyte_lookup[temp & 0xff]) << 24
                value |= (self.crc_mbyte_lookup[(temp >> 8) & 0xff]) << 16
                value |= (self.crc_mbyte_lookup[(temp >> 16) & 0xff]) << 8
                value |= self.crc_mbyte_lookup[(temp >> 24) & 0xff]
        self.crc_def_result = value ^ self.crc_finalize

    #
    def crc_def_finalize(self):
        if self.crc_def_result == self.crc_value:
            self.crc_flag_okay = True
        self.crc_flag_done = False
        self.crc_flag_checked = True

    #
    def crc_def_create_poly_table(self):
        for i in range(0, 256):
            current = i << self.crc_shift[self.crc_type]
            for _ in range(0, 8):
                if current & (self.crc_msb[self.crc_type]):
                    current <<= 1
                    current &= self.crc_mask[self.crc_type]
                    current ^= self.crc_poly
                else:
                    current <<= 1
                    current &= self.crc_mask[self.crc_type]
            self.crc_poly_lookup[int(i)] = current

    #
    def crc_def_create_mbyte_table(self):
        for i in range(0, 256):
            result = 0
            b = i
            for _ in range(0, 8):
                result = (result << 1) + (b & 1)
                b >>= 1
            self.crc_mbyte_lookup[i] = result


# file end