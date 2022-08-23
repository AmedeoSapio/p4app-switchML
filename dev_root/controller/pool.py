#  Copyright 2021 Intel-KAUST-Microsoft
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging


class Pool(object):

    def __init__(self):

        self.log = logging.getLogger(__name__)

        # Maximum register size (from configuration.p4)
        self.register_size = 16384

        self.allocated = {}
        self.free_blocks = {0: self.register_size}

    def allocate(self, size):
        ''' Allocate a block of slots of a certain size.

            Keyword arguments:
                size -- requested size

            Returns:
                (success flag, base index or error message and
                actual size of the allocated block)
        '''

        if size == 0:
            # Invalid input
            return (False, "Size cannot be 0", 0)

        # Select the smallest free block large enough
        # and the largest free block as backup
        selected_block = None
        backup_block = None
        for block in self.free_blocks.items():
            if size <= block[1] and (selected_block is None or selected_block[1] > block[1]):
                selected_block = block
            if backup_block is None or backup_block[1] < block[1]:
                backup_block = block

        if selected_block is None:
            # Unable to allocate this block
            if backup_block is None:
                # No block available
                return (False, "No block available", 0)
            else:
                # Allocate largest block available
                selected_block = backup_block
                size = backup_block[1]

        # Allocate this block
        self.free_blocks.pop(selected_block[0])

        if selected_block[1] == size:
            # The block was perfectly fitting
            self.allocated.update([selected_block])
            return (True, selected_block[0], selected_block[1])
        else:
            self.free_blocks[selected_block[0]+size] = selected_block[1]-size
            self.allocated[selected_block[0]] = size
            return (True, selected_block[0], size)

    def deallocate(self, base_index):
        ''' Deallocate a previously allocated block of slots starting at a certain index.

            Keyword arguments:
                base_index -- base index of the block

            Returns:
                True if the deallocation is successful,
                False if no block was allocated at that base index.
        '''

        if base_index not in self.allocated:
            # This block was not allocated
            return False

        # Deallocate the block
        block_size = self.allocated.pop(base_index)

        # Defragmentation
        for i, s in self.free_blocks.items():
            if i+s == base_index:
                # Found a contiguous free block before
                for ii, ss in self.free_blocks.items():
                    if ii == base_index+block_size:
                        # Found also a contiguous free block after
                        # -> merge the 3 blocks
                        self.free_blocks[i] = s+block_size + \
                            self.free_blocks.pop(ii)
                        return True
                # Merge with the existing block
                self.free_blocks[i] = s+block_size
                return True
            if i == base_index+block_size:
                # Found a contiguous free block after
                for ii, ss in self.free_blocks.items():
                    if ii+ss == base_index:
                        # Found also a contiguous free block before
                        # -> merge the 3 blocks
                        self.free_blocks[ii] = ss+block_size + \
                            self.free_blocks.pop(i)
                        return True
                # Create a new block and merge with the existing one
                self.free_blocks[base_index] = block_size + \
                    self.free_blocks.pop(i)
                return True
        # No other contiguous free block found
        # -> add the new block
        self.free_blocks[base_index] = block_size
        return True

    def verify(self):
        ''' Verify that the status of the pool is correct.

            Returns:
                True if the status is correct, False otherwise.
        '''

        # Check that there is no block both free and updated
        for k in self.free_blocks:
            if k in self.allocated:
                return False

        all_blocks = list(self.free_blocks.items())
        all_blocks.extend(self.allocated.items())

        # Sort blocks
        all_blocks = sorted(all_blocks, key=lambda x: x[0])

        # Check that free and allocated blocks are contiguous
        for i in range(len(all_blocks)-1):
            if all_blocks[i][0]+all_blocks[i][1] != all_blocks[i+1][0]:
                return False

        # Check that the last block is up to register_size
        if all_blocks[-1][0]+all_blocks[-1][1] != self.register_size:
            return False
        return True
