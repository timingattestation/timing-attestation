//© 2009-2012 The MITRE Corporation. ALL RIGHTS RESERVED.
//Permission to use, copy, modify, and distribute this software for any
//purpose with or without fee is hereby granted, provided that the above
//copyright notice and this permission notice appear in all copies.
//THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include "server_client_protocol.h"

//I have no idea why this stupid thing couldn't be linked into this file when it was
//defined in server_client_protocol.cpp...so moving it here was a gross hack
char * MsgTypeToString(msgType m){
	switch(m){
		case SELF_ATTESTATION: 
			return "SELF_ATTESTATION";
		case ERROR_MSG: 
			return "ERROR_MSG";
		case TIMING_TEST: 
			return "TIMING_TEST";
		case TICKSTAMP_ATTESTATION:
			return "TICKSTAMP_ATTESTATION";
		case TOGGLE_ATTACK:
			return "TOGGLE_ATTACK";
	}
	return NULL;
}