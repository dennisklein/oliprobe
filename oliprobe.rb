#!/usr/bin/env ruby

# This code is taken from the NetflowFu library for Ruby.
# Copyright (C) 2011 Davide Guerri
# Adapted to act as nProbe by
# Copyright (C) 2018 Dennis Klein <d.klein@gsi.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require 'packetfu'
require 'json'

# Definition of the Netflow v5 protocol
# https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
# 
# Example
# https://www.ntop.org/nprobe/why-nprobejsonzmq-instead-of-native-sflownetflow-support-in-ntopng/
#
# nProbe indexes
# https://www.ntop.org/guides/nProbe/flow_information_elements.html

module PacketFu
  class NetflowHeader < Struct.new(:netflow_version)
    include StructFu

    def initialize(args={})
      super(Int16.new(args[:netflow_version]))
    end

    def self.version(str)
      str[0, 2].unpack("n")[0]
    end
  end

  class Netflow5Flow < Struct.new(
    :source_ip,
    :destination_ip,
    :nexthop,
    :input_interface,
    :output_interface,
    :packets,
    :octets,
    :first_uptime,
    :last_uptime,
    :source_port,
    :destination_port,
    :pad_1,
    :tcp_flags,
    :proto,
    :tos,
    :source_as,
    :destination_as,
    :source_netmask,
    :destination_netmask,
    :pad_2
  )
    include StructFu

    def initialize(args={})
      super(
          Int32.new(args[:source_ip]),
          Int32.new(args[:destination_ip]),
          Int32.new(args[:nexthop]),
          Int16.new(args[:input_interface]),
          Int16.new(args[:output_interface]),
          Int32.new(args[:packets]),
          Int32.new(args[:octets]),
          Int32.new(args[:first_uptime]),
          Int32.new(args[:last_uptime]),
          Int16.new(args[:source_port]),
          Int16.new(args[:destination_port]),
          Int8.new(0x00), # Pad_1
          Int8.new(args[:tcp_flags]),
          Int8.new(args[:proto]),
          Int8.new(args[:tos]),
          Int16.new(args[:source_as]),
          Int16.new(args[:destination_as]),
          Int8.new(args[:source_netmask]),
          Int8.new(args[:destination_netmask]),
          Int16.new(0x0000) # Pad_2
      )
    end

    # Reads a string to populate the object.
    def read(str)
      PacketFu.force_binary(str)

      return self if (!str.respond_to? :to_s || str.nil?)
      self[:source_ip].read(str[0, 4])
      self[:destination_ip].read(str[4, 4])
      self[:nexthop].read(str[8, 4])
      self[:input_interface,].read(str[12, 2])
      self[:output_interface].read(str[14, 2])
      self[:packets].read(str[16, 4])
      self[:octets].read(str[20, 4])
      self[:first_uptime].read(str[24, 4])
      self[:last_uptime].read(str[28, 4])
      self[:source_port].read(str[32, 2])
      self[:destination_port].read(str[34, 2])
      self[:pad_1].read(str[36, 1])
      self[:tcp_flags].read(str[37, 1])
      self[:proto].read(str[38, 1])
      self[:tos].read(str[39, 1])
      self[:source_as].read(str[40, 2])
      self[:destination_as].read(str[42, 2])
      self[:source_netmask].read(str[44, 1])
      self[:destination_netmask].read(str[45, 1])
      self[:pad_2].read(str[46, 2])

      self
    end

    def to_hash
      {
        1 => self[:octets].to_i,
        2 => self[:packets].to_i,
        4 => self[:proto].to_i,
        5 => self[:tos].to_i,
        6 => self[:tcp_flags].to_i,
        7 => self[:source_port].to_i,
        8 => IPAddr.new(self[:source_ip].to_i, Socket::AF_INET).to_s,
        9 => self[:source_as].to_i,
        10 => self[:input_interface].to_i,
        11 => self[:destination_port].to_i,
        12 => IPAddr.new(self[:destination_ip].to_i, Socket::AF_INET).to_s,
        13 => self[:destination_as].to_i,
        14 => self[:output_interface].to_i,
        15 => IPAddr.new(self[:nexthop].to_i, Socket::AF_INET).to_s,
        21 => self[:last_uptime].to_i,
        22 => self[:first_uptime].to_i,
      }
    end
  end

  class Netflow5Flows < Array
    include StructFu

    # Reads a string to populate the object.
    def read(str)
      self.clear
      PacketFu.force_binary(str)

      return self if (!str.respond_to? :to_s || str.nil?)
      i = 0
      while i < str.to_s.size
        this_flow = Netflow5Flow.new.read(str[i, str.size])
        self << this_flow
        i += this_flow.sz
      end
      self
    end
  end

  class Netflow5 < Struct.new(
    :version,
    :flows_count,
    :uptime,
    :unix_seconds,
    :unix_nanoseconds,
    :flow_sequence_number,
    :engine_type,
    :engine_id,
    :sampling_info,
    :flows
  )
    include StructFu

    def initialize(args={})
      super(
          Int16.new(args[:version]),
          Int16.new(args[:flows_count]),
          Int32.new(args[:uptime]),
          Int32.new(args[:unix_seconds]),
          Int32.new(args[:unix_nanoseconds]),
          Int32.new(args[:flow_sequence_number]),
          Int8.new(args[:engine_type]),
          Int8.new(args[:engine_id]),
          Int16.new(args[:sampling_info]),
          Netflow5Flows.new.read(args[:flows])
      )
    end

    # Reads a string to populate the object.
    def read(str)
      PacketFu.force_binary(str)

      return self if str.nil?
      self[:version].read(str[0, 2])
      self[:flows_count].read(str[2, 2])
      self[:uptime].read(str[4, 4])
      self[:unix_seconds].read(str[8, 4])
      self[:unix_nanoseconds].read(str[12, 4])
      self[:flow_sequence_number].read(str[16, 4])
      self[:engine_type].read(str[20, 1])
      self[:engine_id].read(str[21, 1])
      self[:sampling_info].read(str[22, 2])
      self[:flows].read(str[24, str.size])

      self
    end
  end
end

packet_array = PacketFu::PcapFile.file_to_array(ARGV[0])
packet_array.each do |p|
  packet = PacketFu::Packet.parse(p)
  version = PacketFu::NetflowHeader.version(packet.payload)
  if version == 5
    netflow5 = PacketFu::Netflow5.new.read(packet.payload)
    netflow5.flows.each do |flow|
      puts flow.to_hash.to_json
    end
  end
end
