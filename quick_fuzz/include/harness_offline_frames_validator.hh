#ifndef _HARNESS_OFFLINE_FRAMES_VALIDATOR_H_
#define _HARNESS_OFFLINE_FRAMES_VALIDATOR_H_

#include "quick_fuzz/proto/offline_wire_formats_for_mutator.pb.h"

using OfflineFrame = ::location::nearby::connections::OfflineFrame;

bool EnsureValidOfflineFrame(OfflineFrame& offline_frame);

#endif //_HARNESS_OFFLINE_FRAMES_VALIDATOR_H_