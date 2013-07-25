#ifndef _MEASUREMENT_SLICES_
#define _MEASUREMENT_SLICES_

/*
	This software is the copyrighted work of MITRE.  No ownership or other proprietary interest in this 
	software is granted to you other than what is granted in this license.     
	 
	MITRE IS PROVIDING THE SOFTWARE "AS IS" AND ACCORDINGLY MAKES NO WARRANTY, EXPRESS OR IMPLIED, AS 
	TO THE ACCURACY, CAPABILITY, EFFICIENCY, MERCHANTABILITY, OR FUNCTIONING  OF THE SOFTWARE AND DOCUMENTATION.  
	IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR SPECIAL 
	DAMAGES RELATED TO THE SOFTWARE, EVEN IF MITRE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.             
	 
	You accept this software on the condition that you indemnify and hold harmless MITRE, its Board of Trustees, 
	officers,  agents, and employees, from any and all liability damages to third parties, including attorneys' 
	fees, court costs, and other related costs and expenses, arising out of your use of this software irrespective 
	of the cause of said liability.
*/

#include "bios_measure.h"

// BIOS revision for which this will be compiled for
#define BIOS_REV						29						// A29, A30, etc ...

/*
	These define the measurement slices for firmware measurement
	
	These are detemermined by comparing the default unpacked smram module
	to that at the point of measurement.
	
*/
#define BIOS_START						0xFFE60000		// starting location of mapped bios in high memory 
#define BIOS_END						0xFFFFFFFF		// same for every E6400 bios revision
#define IVT_LEN							0x1E0			// on this system, the IVT only occupies bytes 0-1DFh ...

#if BIOS_REV == 29
#define NUM_SLICES   					3				// change this to as many linear range measurements as you want to make, this is 4 just to show some examples
#define RET_CTRL_FLOW					0xDEADBEEF		// The address of the funciton you hooked to call this code

#elif BIOS_REV == 30
#define NUM_SLICES   					2
#define RET_CTRL_FLOW					0xDEADBEEF		// The address of the funciton you hooked to call this code

#elif BIOS_REV == 31
#define NUM_SLICES   					2
#define RET_CTRL_FLOW					0xDEADBEEF		// The address of the funciton you hooked to call this code

#elif BIOS_REV == 32
#define NUM_SLICES   					2
#define RET_CTRL_FLOW					0xDEADBEEF		// The address of the funciton you hooked to call this code

#endif

unsigned int measurementSlices[NUM_SLICES][2];

#endif