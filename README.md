High Level Analyzer - Addon: Stream Parser

For more information and documentation about the product and framework, please go to
https://support.saleae.com/extensions/high-level-analyzer-extensions

The software is provided as it is without any liability and without any warranty.
The author will take no responsibility and can't deliver any support.

A stream packet can contain the following parts:
- Time to Packet: before a new packet start, it looks for an idle time in ms, max=1s
- Preamble      : number of unchecked bytes
- Header        : 0-8 bytes, no need to insert ending '0'; left aligned like the incoming stream
- Header Pad    : number of unchecked bytes
- Length        : 0-2 bytes to specify the packet length; 0 => the menu 'length fix' is used  
- Length Pad    : number of unchecked bytes
- DATA          : number = packet length - options
- Data Pad      : number of unchecked bytes (is not part of crc)
- Crc           : 0-4 bytes crc checksum
- Crc Pad       : number of unchecked bytes to reach packet end
- Packed Pad    : the left over if a fixed packed length is behind Crc Pad (packet_fix_length - length)

- Header Mask   : Stream bytes and mask == Header and mask? if mask==0 => everything is a match
- Tigger Mask   : is operated to the stream header if the
- Tigger Value  : Header and Trigger Mask == Trigger Value and Trigger Mask => Trigger set
- Trigger Time Max  : if Trigger Set: Trigger Time starts at packet end => True next frame before Tmax
- Packet timeout    : resets the current parsing in ms
- Packet fix length : specifies the total packet length
- Length fix        : if Length == 0 => specifies the length for data and crc
- Length Offset     : can be used to adjust the data length

flex search means the header length is determent by the header value input, inputs can have different lengths
- Time_to_Packet == 0, Header_length == 0,  => Packet starts after flex Header match
- Time_to_Packet == 0, Header_length >  0,  => Packet starts after fix Header length match
- Time_to_Packet >  0, Header_length == 0,  => Packet starts after Time to Header (Idle)
- Time_to_Packet >  0, Header_length >  0,  => Packet starts after Idle and fix Header length match

- Time_to_Packet == 0, Header_length == 0,  Header_value      => Packet starts after Idle
- a double P-End indicates that the packet length is shorter than the packet definition

A pad(ding) is used to jump over packet bytes which can't be handled by this parser
 
There are almost no plausibility check => define '....' and you get something

open topics
- crc implementation: please implement it according to your own needs
	  there is no crc32, it is just a place holder
      there will be no update on this topic
- error handling e.g. Stream error
      so fare there was no need to handle errors
      nothing planed on this topic

topics that could be improved
- output after timeout and potential header
