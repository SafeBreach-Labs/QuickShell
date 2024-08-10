import base64
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.message import DecodeError

from quick_share.proto.offline_wire_formats_pb2 import OfflineFrame
from quick_share.proto.wire_format_pb2 import Frame

def is_sub_key_in_dict(checked_dict, *keys):
    for key in keys:
        if not key in checked_dict.keys():
            return False
        checked_dict = checked_dict[key]
    
    return True


def decode_payload_transfer_internal_bytes_frame_protobuf(data):
    secure_message = Frame()
    secure_message.ParseFromString(data)
    secure_message_dict = MessageToDict(secure_message)
    return secure_message_dict


def decode_offline_frame_protobuf_bytes(data):
    offline_frame = OfflineFrame()
    offline_frame.ParseFromString(data)
    offline_frame_dict = MessageToDict(offline_frame)

    if offline_frame_dict["v1"]["type"] == "PAYLOAD_TRANSFER" and offline_frame_dict["v1"]["payloadTransfer"]["payloadHeader"]["type"] == "BYTES" and is_sub_key_in_dict(offline_frame_dict, "v1", "payloadTransfer", "payloadChunk", "body"):
        try:
            offline_frame_dict["v1"]["payloadTransfer"]["payloadChunk"]["body"] = decode_payload_transfer_internal_bytes_frame_protobuf(base64.b64decode(offline_frame_dict["v1"]["payloadTransfer"]["payloadChunk"]["body"]))
        except DecodeError:
            pass

    return offline_frame_dict


def offline_frame_dict_to_offline_frame(offline_frame_dict):
    if offline_frame_dict["v1"]["type"] == "PAYLOAD_TRANSFER" and offline_frame_dict["v1"]["payloadTransfer"]["payloadHeader"]["type"] == "BYTES" and is_sub_key_in_dict(offline_frame_dict, "v1", "payloadTransfer", "payloadChunk", "body") and isinstance(offline_frame_dict["v1"]["payloadTransfer"]["payloadChunk"]["body"], dict):
        internal_payload_transfer_bytes_frame = Frame()
        ParseDict(offline_frame_dict["v1"]["payloadTransfer"]["payloadChunk"]["body"], internal_payload_transfer_bytes_frame)
        payload_chunk_bytes_base64 = base64.b64encode(internal_payload_transfer_bytes_frame.SerializeToString())
        offline_frame_dict["v1"]["payloadTransfer"]["payloadChunk"]["body"] = payload_chunk_bytes_base64

    offline_frame = OfflineFrame()
    ParseDict(offline_frame_dict, offline_frame)
    return offline_frame
