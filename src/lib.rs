#![no_std]
#![deny(unused_crate_dependencies)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{borrow::ToOwned, iter, vec::Vec};

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, vec::Vec};

#[cfg(not(feature = "std"))]
use core::iter;

use raptorq::{partition, EncodingPacket, ObjectTransmissionInformation, SourceBlockDecoder};

pub trait LimitedDecoderMemory<A: ExternalAddress> {
    const PACKET_SIZE: u16;
    const PACKET_WITH_ID_SIZE: u16 = Self::PACKET_SIZE + 4;
    const DECODER_MEMORY: u64;
    fn write_external(&mut self, address: &A, data: &[u8]);
    fn read_external(&mut self, address: &A, len: usize) -> Vec<u8>;
}

pub trait ExternalAddress: Copy {
    fn shift(&mut self, position: usize);
}

pub struct DataAtAddress<A: ExternalAddress> {
    pub start_address: A,
    pub total_len: usize,
}

pub struct DecoderMetal<A: ExternalAddress> {
    start_address: A,
    config: ObjectTransmissionInformation,
    block_decoders: BlockDecodersMetal<A>,
    blocks: BlocksMetal,
}

pub struct BlocksMetal {
    filled: Vec<bool>,
    block_len_1: usize,
    block_len_2: usize,
    zl: usize,
}

pub struct BlockDecodersMetal<A: ExternalAddress> {
    pub set_sbd: Vec<SourceBlockDecoderMetal<A>>,
    pub next_address_to_use: A,
}

pub struct SourceBlockDecoderMetal<A: ExternalAddress> {
    pub sbd_husk: SourceBlockDecoder,
    pub repair_packets_storage: Vec<A>,
}

impl<A: ExternalAddress> BlockDecodersMetal<A> {
    pub fn restore_sbd<L>(&self, lm: &mut L, i: usize) -> SourceBlockDecoder
    where
        L: LimitedDecoderMemory<A>,
    {
        let mut repair_packets: Vec<EncodingPacket> = Vec::new();
        for address in self.set_sbd[i].repair_packets_storage.iter() {
            let packet_data = lm.read_external(address, L::PACKET_WITH_ID_SIZE as usize);
            let packet = EncodingPacket::deserialize(&packet_data);
            repair_packets.push(packet);
        }
        let mut out = self.set_sbd[i].sbd_husk.to_owned();
        out.repair_packets = repair_packets;
        out
    }
    pub fn decode<L>(&mut self, lm: &mut L, i: usize, packet: EncodingPacket) -> Option<Vec<u8>>
    where
        L: LimitedDecoderMemory<A>,
    {
        let serialized_packet_data = packet.serialize();
        let mut source_block_decoder_i = self.restore_sbd::<L>(lm, i);
        let decode_result = source_block_decoder_i.decode(iter::once(packet));
        match decode_result {
            Some(a) => Some(a),
            None => {
                if self.set_sbd[i].repair_packets_storage.len()
                    < source_block_decoder_i.repair_packets.len()
                {
                    // added the packet into repair set
                    let current_address = self.next_address_to_use;
                    lm.write_external(&current_address, &serialized_packet_data);
                    self.set_sbd[i].repair_packets_storage.push(current_address);
                    self.next_address_to_use
                        .shift(L::PACKET_WITH_ID_SIZE as usize);
                }
                let mut new_sbd_husk_i = source_block_decoder_i;
                new_sbd_husk_i.repair_packets = Vec::new();
                self.set_sbd[i].sbd_husk = new_sbd_husk_i;
                None
            }
        }
    }
}

impl<A: ExternalAddress> DecoderMetal<A> {
    pub fn new<L>(payload_length: usize, start_address: A) -> Self
    where
        L: LimitedDecoderMemory<A>,
    {
        let config = ObjectTransmissionInformation::generate_encoding_parameters_exposed(
            payload_length as u64,
            L::PACKET_SIZE,
            L::DECODER_MEMORY,
        );

        let kt = {
            if config.transfer_length() % (config.symbol_size() as u64) == 0 {
                (config.transfer_length() / (config.symbol_size() as u64)) as u32
            } else {
                (config.transfer_length() / (config.symbol_size() as u64) + 1) as u32
            }
        };

        let (kl, ks, zl, zs) = partition(kt, config.source_blocks());

        let block_len_1 = u64::from(kl) * u64::from(config.symbol_size());
        let block_len_2 = u64::from(ks) * u64::from(config.symbol_size());
        let total_blocks_len = ((zl as u64) * block_len_1 + (zs as u64) * block_len_2) as usize;

        let mut set_sbd = vec![];
        for i in 0..zl {
            let sbd_husk = SourceBlockDecoder::new2(i as u8, &config, block_len_1);
            set_sbd.push(SourceBlockDecoderMetal {
                sbd_husk,
                repair_packets_storage: Vec::new(),
            })
        }

        for i in zl..(zl + zs) {
            let sbd_husk = SourceBlockDecoder::new2(i as u8, &config, block_len_2);
            set_sbd.push(SourceBlockDecoderMetal {
                sbd_husk,
                repair_packets_storage: Vec::new(),
            })
        }

        let mut next_address_to_use = start_address;
        next_address_to_use.shift(total_blocks_len);

        Self {
            start_address,
            config,
            block_decoders: BlockDecodersMetal {
                set_sbd,
                next_address_to_use,
            },
            blocks: BlocksMetal {
                filled: vec![false; (zl + zs) as usize],
                block_len_1: block_len_1 as usize,
                block_len_2: block_len_2 as usize,
                zl: zl as usize,
            },
        }
    }

    pub fn add_new_packet<L>(&mut self, lm: &mut L, packet: EncodingPacket)
    where
        L: LimitedDecoderMemory<A>,
    {
        let block_number = packet.payload_id().source_block_number() as usize;
        if !self.blocks.filled[block_number] {
            if let Some(block_data) = self.block_decoders.decode::<L>(lm, block_number, packet) {
                let mut to_address = self.start_address;
                if block_number <= self.blocks.zl {
                    to_address.shift(block_number * self.blocks.block_len_1)
                } else {
                    to_address.shift(
                        self.blocks.zl * self.blocks.block_len_1
                            + (block_number - self.blocks.zl) * self.blocks.block_len_2,
                    )
                }
                lm.write_external(&to_address, &block_data);
                self.blocks.filled[block_number] = true;
            }
        }
    }

    pub fn get_result(&self) -> Option<DataAtAddress<A>> {
        for block_flag in self.blocks.filled.iter() {
            if !block_flag {
                return None;
            }
        }
        Some(DataAtAddress {
            start_address: self.start_address,
            total_len: self.config.transfer_length() as usize,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{seq::SliceRandom, Fill};

    #[derive(Clone, Copy, Debug)]
    struct Position(usize);

    impl ExternalAddress for Position {
        fn shift(&mut self, position: usize) {
            self.0 += position;
        }
    }

    struct ExternalMemoryMock;

    static mut EM: [u8; 2_000_000] = [0u8; 2_000_000];

    impl LimitedDecoderMemory<Position> for ExternalMemoryMock {
        const PACKET_SIZE: u16 = 248;
        const DECODER_MEMORY: u64 = 4096;
        fn write_external(&mut self, address: &Position, data: &[u8]) {
            unsafe {
                EM[address.0..address.0 + data.len()].copy_from_slice(data);
            }
        }
        fn read_external(&mut self, address: &Position, len: usize) -> Vec<u8> {
            unsafe { EM[address.0..address.0 + len].to_vec() }
        }
    }

    const MOCK_DATA_LEN: u64 = 400_000;

    #[test]
    fn full_cycle() {
        let mut rng = rand::thread_rng();

        let mut mock_data = [0; MOCK_DATA_LEN as usize];
        mock_data.try_fill(&mut rng).unwrap();

        let config = ObjectTransmissionInformation::generate_encoding_parameters_exposed(
            MOCK_DATA_LEN,
            ExternalMemoryMock::PACKET_SIZE,
            ExternalMemoryMock::DECODER_MEMORY,
        );
        let encoder = raptorq::Encoder::new(&mock_data, config);
        let mut packets = encoder
            .get_encoded_packets(MOCK_DATA_LEN as u32 / ExternalMemoryMock::PACKET_SIZE as u32);

        packets.shuffle(&mut rng);

        let mut decoder =
            DecoderMetal::new::<ExternalMemoryMock>(MOCK_DATA_LEN as usize, Position(0usize));

        let mut external_memory_mock = ExternalMemoryMock;

        for packet in packets {
            decoder.add_new_packet(&mut external_memory_mock, packet);
            if decoder.get_result().is_some() {
                break;
            }
        }

        match decoder.get_result() {
            Some(data_at_address) => {
                assert_eq!(data_at_address.start_address.0, 0);
                assert_eq!(data_at_address.total_len, MOCK_DATA_LEN as usize);
                assert_eq!(
                    external_memory_mock
                        .read_external(&data_at_address.start_address, data_at_address.total_len),
                    mock_data
                );
            }
            None => panic!("all blocks used, still none"),
        }
    }
}
