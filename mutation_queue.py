# xss_security_gui/mutation_queue.py

from queue import PriorityQueue

# Приоритетная очередь:
# чем выше риск — тем раньше мутант пойдёт в атаку
MUTATION_ATTACK_QUEUE = PriorityQueue()