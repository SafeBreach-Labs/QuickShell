import socket
import psutil

def calc_bigger_in_percentage(num, bigger_num):
    print(f"num: {num}, bigger_num: {bigger_num}")
    if num >= bigger_num:
        return 0
    
    return (bigger_num / num) * 100 - 100

def get_closest(num_list, target_num):
    abs_diff_function = lambda x : abs(x - target_num)
    closest_value = min(num_list, key = abs_diff_function)
    return closest_value
