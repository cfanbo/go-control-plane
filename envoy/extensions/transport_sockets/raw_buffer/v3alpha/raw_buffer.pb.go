// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/extensions/transport_sockets/raw_buffer/v3alpha/raw_buffer.proto

package envoy_extensions_transport_sockets_raw_buffer_v3alpha

import (
	fmt "fmt"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type RawBuffer struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RawBuffer) Reset()         { *m = RawBuffer{} }
func (m *RawBuffer) String() string { return proto.CompactTextString(m) }
func (*RawBuffer) ProtoMessage()    {}
func (*RawBuffer) Descriptor() ([]byte, []int) {
	return fileDescriptor_2332ec5eca1b00f8, []int{0}
}

func (m *RawBuffer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RawBuffer.Unmarshal(m, b)
}
func (m *RawBuffer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RawBuffer.Marshal(b, m, deterministic)
}
func (m *RawBuffer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RawBuffer.Merge(m, src)
}
func (m *RawBuffer) XXX_Size() int {
	return xxx_messageInfo_RawBuffer.Size(m)
}
func (m *RawBuffer) XXX_DiscardUnknown() {
	xxx_messageInfo_RawBuffer.DiscardUnknown(m)
}

var xxx_messageInfo_RawBuffer proto.InternalMessageInfo

func init() {
	proto.RegisterType((*RawBuffer)(nil), "envoy.extensions.transport_sockets.raw_buffer.v3alpha.RawBuffer")
}

func init() {
	proto.RegisterFile("envoy/extensions/transport_sockets/raw_buffer/v3alpha/raw_buffer.proto", fileDescriptor_2332ec5eca1b00f8)
}

var fileDescriptor_2332ec5eca1b00f8 = []byte{
	// 196 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x72, 0x4b, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xad, 0x28, 0x49, 0xcd, 0x2b, 0xce, 0xcc, 0xcf, 0x2b, 0xd6, 0x2f, 0x29, 0x4a,
	0xcc, 0x2b, 0x2e, 0xc8, 0x2f, 0x2a, 0x89, 0x2f, 0xce, 0x4f, 0xce, 0x4e, 0x2d, 0x29, 0xd6, 0x2f,
	0x4a, 0x2c, 0x8f, 0x4f, 0x2a, 0x4d, 0x4b, 0x4b, 0x2d, 0xd2, 0x2f, 0x33, 0x4e, 0xcc, 0x29, 0xc8,
	0x48, 0x44, 0x12, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x32, 0x05, 0x9b, 0xa3, 0x87, 0x30,
	0x47, 0x0f, 0xc3, 0x1c, 0x3d, 0x24, 0x4d, 0x50, 0x73, 0xa4, 0x14, 0x4b, 0x53, 0x0a, 0x12, 0xf5,
	0x13, 0xf3, 0xf2, 0xf2, 0x4b, 0x12, 0x4b, 0xc0, 0xd6, 0x97, 0xa5, 0x16, 0x81, 0xf4, 0x67, 0xe6,
	0xa5, 0x43, 0x4c, 0x56, 0xf2, 0xe4, 0xe2, 0x0c, 0x4a, 0x2c, 0x77, 0x02, 0xeb, 0xb3, 0xb2, 0x99,
	0x75, 0xb4, 0x43, 0xce, 0x9c, 0x0b, 0x6a, 0x5b, 0x72, 0x7e, 0x5e, 0x5a, 0x66, 0x3a, 0x86, 0x4d,
	0x28, 0x16, 0x19, 0xe9, 0xc1, 0x75, 0x3b, 0x85, 0x73, 0x39, 0x67, 0xe6, 0xeb, 0x81, 0xf5, 0x16,
	0x14, 0xe5, 0x57, 0x54, 0xea, 0x91, 0xe5, 0x68, 0x27, 0x3e, 0xb8, 0x89, 0x01, 0x20, 0x17, 0x06,
	0x30, 0x26, 0xb1, 0x81, 0x9d, 0x6a, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff, 0xae, 0xa5, 0x7e, 0x2d,
	0x4e, 0x01, 0x00, 0x00,
}