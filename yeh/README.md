# Yeh-Protocol
Yeh et al. Protocol. In 2010, Yeh et al. [39] proposed
a process oriented UMAP. The feature that differentiates
this protocol from its predecessors is the DoS avoidance
mechanism. In this protocol, the pairs of latest dynamic
variables are stored at the reader side instead of the tag. The
reader also maintains a flag to identify whether the tag/reader
pair is fully synchronized or not.The nontriangular function
used in the protocol is the rotation function (𝑅𝑜𝑡(𝑎, 𝑏)). The
memory architecture of the UMAP is given in Table 5. The
working principle of the Yeh et al. protocol is as follows: the
protocol is the rotation function (𝑅𝑜𝑡(𝑎, 𝑏)). The memory
architecture of the UMAP is as follows:

(1) The reader initiates the communication by sending a
“Hello” message to the tag.

(2) As a response, the tag transmits the 𝐼𝐷𝑆 stored in its
dynamic memory.

(3) After successful tag identification through the
database, the reader generates two pseudorandom numbers 𝑛1 and 𝑛2. 
If the 𝐼𝐷𝑆 = 𝐼𝐷𝑆𝑛𝑒𝑤, the reader sets an internal flag 𝑓 = 0; otherwise
the flag’s value sets to 1, the key 𝐾 updates and becomes equal to
the tag’s 𝐼𝐷. After key updation, the reader calculates
and sends message 𝑋 = 𝐴 ‖ 𝐵 ‖ 𝐶 ‖ 𝑓 to the tag.

𝐴 = (𝐼𝐷𝑆 ⊕𝐾 ) ⊕ 𝑛1

𝐵 = (𝐼𝐷𝑆 ∨ 𝐾) ⊕ 𝑛2

𝐾∗ = 𝑅𝑜𝑡 (𝐾 ⊕𝑛2, 𝑛1)

𝐶 = (𝐾∗ ⊕ 𝑛1) + 𝑛2

𝑓 = 𝑓𝑙𝑎𝑔 𝑏𝑖𝑡

𝑓 = 0 𝑖𝑓 𝐼𝐷𝑆 = 𝐼𝐷𝑆𝑁𝐸𝑊

𝑓 = 1 𝑖𝑓 𝐼𝐷𝑆 = 𝐼𝐷𝑆𝑂𝐿𝐷

(4) Upon receiving the challenge message, the tag updates
the value of the key 𝐾 based on the flag status.
After that 𝑛1 and 𝑛2 are extracted and the reader is
authenticated.

(5) The successful reader verification leads to the calculation
and transmission of the tag authentication
challenge message 𝐷.

𝐾̈* = 𝑅𝑜𝑡 (𝐾 ⊕𝑛1, 𝑛2)

𝐷 = (𝐾̈ ∗ ⊕ 𝑛2) + 𝑛1

(6) In case of successful mutual authentication, the
dynamic memory on both sides is updated.

𝐼𝐷𝑆𝑁𝑒𝑤 = (𝐼𝐷𝑆 + (𝐼𝐷 ⊕ 𝐾̈ ∗)) ⊕𝑛1⊕ 𝑛2

𝐾𝑁𝑒𝑤 = 𝐾∗



