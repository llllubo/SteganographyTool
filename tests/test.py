#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
**Tests for Steganography Tool**

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
""" 


import os
import random
import re
import sys
import subprocess

import matplotlib.pyplot as plt
import numpy as np


EXE_PATH = "./executables/"
"""
Path to the all executables, which are going to be used by test cases.
"""

MESS_PATH = "./data/"
"""
Path to the all secret messages, which are going to be used by test cases.
"""


def test_encoding_rates():
    """
    Test case for encoding rate analysis.
    """

    files = []
    values_sub = []
    values_ext_sub = []
    values_nops = []
    values_all = []
    
    for fname in os.listdir(EXE_PATH):
                
        fpath = os.path.join(EXE_PATH, fname)
        
        for m in ("sub", "ext-sub", "nops", "ext-sub-nops"):
            
            # NEED TO USE OPTION TO SUPPRESS ENCRYPTION.
            cmd = f"python3 ../src/main.py -v " + "analyze" + \
                " -m " + f"{m}" + \
                f" -c {fpath}"
            
            try:
                b_lines = subprocess.check_output(
                        cmd,
                        stderr=subprocess.STDOUT,
                        shell=True)
            except subprocess.CalledProcessError as e:
                print(f"ERROR! Can not run command: {cmd}\n{e.output.decode()}", file=sys.stderr)
                sys.exit(1)
            
            lines = b_lines.decode()

            analysis = re.search(r'\s+(?P<rate>[0-9\.,]+)\sencoding\srate', lines)
            
            if analysis is None:
                print(f"ERROR! Parsing Encoding Rate", file=sys.stderr)
                sys.exit(1)
            
            rate = float(analysis.group("rate").replace(",",""))
            if m == "sub":
                values_sub.append(rate)
            elif m == "ext-sub":
                values_ext_sub.append(rate)
            elif m == "nops":
                values_nops.append(rate)
            else:
                values_all.append(rate)
            
        files.append(fname)
        
    ## PRINT STATISTICS
    print("ENCODING RATES:\n")
    
    max_value = max(values_nops)
    min_value = min(values_nops)
    avg_value = 0 if len(values_nops) == 0 else sum(values_nops)/len(values_nops)
    print("nops:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(values_sub)
    min_value = min(values_sub)
    avg_value = 0 if len(values_sub) == 0 else sum(values_sub)/len(values_sub)
    print("sub:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(values_ext_sub)
    min_value = min(values_ext_sub)
    avg_value = 0 if len(values_ext_sub) == 0 else sum(values_ext_sub)/len(values_ext_sub)
    print("ext-sub:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(values_all)
    min_value = min(values_all)
    avg_value = 0 if len(values_all) == 0 else sum(values_all)/len(values_all)
    print("ext-sub-nops:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    ## PLOT RESULTS
    width = 0.225
    x = np.arange(len(files))

    fig, ax = plt.subplots(figsize=(8,6))
    plt.setp(ax.get_xticklabels(), rotation=45, horizontalalignment='right')
    ax.bar(x - 3*width/2, values_nops, width, label='Metóda nops')
    ax.bar(x - width/2, values_sub, width, label='Metóda sub')
    ax.bar(x + width/2, values_ext_sub, width, label='Metóda ext-sub')
    ax.bar(x + 3*width/2, values_all, width, label='Kombinácia metód')

    ax.set_xlabel('Spustiteľné súbory')
    ax.set_ylabel('Rýchlosť vkladania')
    ax.set_title('Rýchlosť vkladania pre súbory ELF a PE')
    ax.set_xticks(x, files)
    ax.legend()

    fig.tight_layout()
    plt.grid(linewidth=0.5, linestyle="--")

    plt.savefig("test_encoding_rates.pdf")
    print("\nGraph was plotted!")

    
def test_time_force():
    """
    Test case for time analysis with/without -f/--force argument.
    """
    
    files = []
    time_f = []
    time_non_f = []
    times_longer = []
    
    # Find some data to embed.
    data = os.listdir(MESS_PATH)
    
    # NEED TO USE OPTION TO SUPPRESS ENCRYPTION.
    cmd = f"python3 ../src/main.py -v " + "embed" + \
        " -m " + "ext-sub-nops" + \
        f" -s {MESS_PATH}{data}" + \
        " -p 'password'" + \
        " -c "
    
    for fname in os.listdir(EXE_PATH):
        
        for force in ("", " -f"):
        
            fpath = os.path.join(EXE_PATH, fname)
            
            try:
                b_lines = subprocess.check_output(
                        cmd + f"{fpath}{force}",
                        stderr=subprocess.STDOUT,
                        shell=True)
            except subprocess.CalledProcessError as e:
                print(f"ERROR! Can not run command: {cmd}{fpath}{force}\n{e.output.decode()}", file=sys.stderr)
                sys.exit(1)
            
            lines = b_lines.decode()

            # Find seconds.
            analysis = re.search(r'---\s(?P<time>[0-9\.,]+)\sseconds ---', lines)
            
            if analysis is None:
                print(f"ERROR! Parsing Time force.", file=sys.stderr)
                sys.exit(1)
            
            # # Remove unexpected comma and take seconds.
            if force == "":
                time_non_f.append(float(analysis.group("time").replace(",","")))
            else:
                time_f.append(float(analysis.group("time").replace(",","")))
    
        times_longer.append(time_f[-1]/time_non_f[-1])
        files.append(fname)
    
    ## PRINT STATISTICS
    print("TIME COMPLEXITY WITH -f & WITHOUT -f:\n")
    
    max_value = max(time_non_f)
    min_value = min(time_non_f)
    avg_value = 0 if len(time_non_f) == 0 else sum(time_non_f)/len(time_non_f)
    print("Time without -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(time_f)
    min_value = min(time_f)
    avg_value = 0 if len(time_f) == 0 else sum(time_f)/len(time_f)
    print("Time with -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(times_longer)
    min_value = min(times_longer)
    avg_value = 0 if len(times_longer) == 0 else sum(times_longer)/len(times_longer)
    print("How many times lasts longer with -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    print("For every executable:")
    for i, _ in enumerate(times_longer):
        print(f"\t{files[i]} -> {times_longer[i]} times longer")

    ## PLOT RESULTS
    x = np.arange(len(files))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8,6))
    plt.setp(ax.get_xticklabels(), rotation=45, horizontalalignment='right')
    ax.bar(x - width/2, time_non_f, width, label='Bez --force')
    ax.bar(x + width/2, time_f, width, label='S --force')

    ax.set_xlabel('Spustiteľné súbory')
    ax.set_ylabel('Doba behu [sekundy]')
    ax.set_title('Doba behu bez prepínača --force a s ním')
    ax.set_xticks(x, files)
    ax.legend()

    plt.grid(linewidth=0.5, linestyle="--")
    fig.tight_layout()

    plt.savefig("test_time_force.pdf")
    print("\nGraph was plotted!")
    
    
def test_capacity_force():
    """
    Test case for capacity analysis with/without -f/--force argument.
    """

    files = []
    cap_f = []
    cap_non_f = []
    times_higher = []
    
    # NEED TO USE OPTION TO SUPPRESS ENCRYPTION.
    cmd = f"python3 ../src/main.py " + "analyze" + \
        " -m " + "ext-sub-nops" + \
        " -c "
    
    for fname in os.listdir(EXE_PATH):
        
        for force in ("", " -f"):
        
            fpath = os.path.join(EXE_PATH, fname)
            
            try:
                b_lines = subprocess.check_output(
                        cmd + f"{fpath}{force}",
                        stderr=subprocess.STDOUT,
                        shell=True)
            except subprocess.CalledProcessError as e:
                print(f"ERROR! Can not run command: {cmd}{fpath}{force}\n{e.output.decode()}", file=sys.stderr)
                sys.exit(1)
            
            lines = b_lines.decode()

            analysis = re.search(r'Maximum:\s+(?P<capacity>[0-9\.,]+)\s+', lines)
            
            if analysis is None:
                print(f"ERROR! Parsing Capacity force.", file=sys.stderr)
                sys.exit(1)
            
            cap = float(analysis.group("capacity").replace(",",""))
            if force == "":
                cap_non_f.append(cap)
            else:
                cap_f.append(cap)
    
        times_higher.append(cap_f[-1]/cap_non_f[-1])
        files.append(fname)
    
    ## PRINT STATISTICS
    print("CAPACITY ANALYSIS WITH -f & WITHOUT -f:\n")
    
    max_value = max(cap_non_f)
    min_value = min(cap_non_f)
    avg_value = 0 if len(cap_non_f) == 0 else sum(cap_non_f)/len(cap_non_f)
    print("Capacity without -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(cap_f)
    min_value = min(cap_f)
    avg_value = 0 if len(cap_f) == 0 else sum(cap_f)/len(cap_f)
    print("Capacity with -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    max_value = max(times_higher)
    min_value = min(times_higher)
    avg_value = 0 if len(times_higher) == 0 else sum(times_higher)/len(times_higher)
    print("How many times bigger capacity with -f:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    print("For every executable:")
    for i, _ in enumerate(files):
        print(f"\t{files[i]} -> {times_higher[i]} times bigger")
    
    ## PLOT RESULTS
    x = np.arange(len(files))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8,6))
    plt.setp(ax.get_xticklabels(), rotation=45, horizontalalignment='right')
    ax.bar(x - width/2, cap_non_f, width, label='Bez --force')
    ax.bar(x + width/2, cap_f, width, label='S --force')

    ax.set_xlabel('Spustiteľné súbory')
    ax.set_ylabel('Kapacita [bajty]')
    ax.set_title('Kapacita bez prepínača --force a s ním')
    ax.set_xticks(x, files)
    ax.legend()

    fig.tight_layout()
    plt.grid(linewidth=0.5, linestyle="--")

    plt.savefig("test_capacity_force.pdf")
    print("\nGraph was plotted!")
    
    
def test_capacity():
    """
    Test case for capacity analysis due to executable size.
    """

    files = []
    values_cap = []
    values_size = []
    values_ratio = []
    
    for fname in os.listdir(EXE_PATH):
                
        fpath = os.path.join(EXE_PATH, fname)
        
        # NEED TO USE OPTION TO SUPPRESS ENCRYPTION.
        cmd = f"python3 ../src/main.py -v " + "analyze" + \
            " -m " + "ext-sub-nops" + \
            f" -c {fpath}"
        
        try:
            b_lines = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    shell=True)
        except subprocess.CalledProcessError as e:
            print(f"ERROR! Can not run command: {cmd}\n{e.output.decode()}", file=sys.stderr)
            sys.exit(1)
        
        lines = b_lines.decode()
        
        analysis_size = re.search(r'Total\ssize\sof\sinstructions:\s+(?P<size>[0-9\.,]+)\s+Bytes', lines)
        analysis_cap = re.search(r'Average:\s+(?P<cap>[0-9\.,]+)\s+Bytes', lines)

        if analysis_size is None or analysis_cap is None:
            print(f"ERROR! Capacity ratio.", file=sys.stderr)
            sys.exit(1)
        
        cap = float(analysis_cap.group("cap").replace(",",""))
        values_cap.append(cap)
        size = float(analysis_size.group("size").replace(",",""))
        values_size.append(size)
        values_ratio.append(cap/size)
        files.append(fname)
        
    ## PRINT STATISTICS
    print("CAPACITY RATIO OF EXECUTABLES:\n")
    
    max_value = max(values_ratio)
    min_value = min(values_ratio)
    avg_value = 0 if len(values_ratio) == 0 else sum(values_ratio)/len(values_ratio)
    print("Capacity ratio:")
    print(f"\tMaximum value: {str(max_value)}")
    print(f"\tMinimum value: {str(min_value)}")
    print(f"\tAverage value: {str(avg_value)}")
    
    print("For every executable:")
    for i, _ in enumerate(values_ratio):
        print(f"\t{files[i]} -> {values_ratio[i]:.2%}")

    ## PLOT RESULTS
    x = np.arange(len(files))

    fig, ax = plt.subplots(figsize=(8,6))
    ax.plot(files, values_ratio)
    plt.setp(ax.get_xticklabels(), rotation=45, horizontalalignment='right')

    ax.set_xlabel('Spustiteľné súbory')
    ax.set_ylabel('Pomer kapacity ku veľkosti súboru')
    ax.set_title('Meranie kapacity súborov vzhľadom k ich veľkosti')
    ax.set_xticks(x, files)
    
    fig.tight_layout()
    plt.grid(linewidth=0.5, linestyle="--")

    plt.savefig("test_capacity.pdf")
    print("\nGraph was plotted!")
    

def run_check():
    """
    Test case for imperceptibility of applied steganography technique.
    """
    exe = EXE_PATH + random.choice(os.listdir("./executables/"))
    cmds = [f"hexdump -b {exe}",
            f"hexdump -c {exe}",
            f"hexdump -C {exe}",
            f"hexdump -d {exe}",
            f"hexdump -n 42 {exe}",
            f"hexdump -o {exe}",
            f"hexdump -s 42 {exe}",
            f"hexdump -v {exe}",
            f"hexdump -x {exe}"]
    
    num = len(cmds)
    
    print("CHECK IMPERCEPTIBILITY OF HEXDUMP:\n")
    
    for idx, cmd in enumerate(cmds):
    
        # Run with origin program utility.
        try:
            b_lines1 = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    shell=True)
        except subprocess.CalledProcessError as e:
            print(f"ERROR! Can not run command: {cmd}\n{e.output.decode()}", file=sys.stderr)
            sys.exit(1)
            
        # Run with modified program utility.
        cmd2 = "./executables/" + cmd
        try:
            b_lines2 = subprocess.check_output(
                    cmd2,
                    stderr=subprocess.STDOUT,
                    shell=True)
        except subprocess.CalledProcessError as e:
            print(f"ERROR! Can not run command {cmd2}\n{e.output.decode()}", file=sys.stderr)
            sys.exit(1)
            
        # Check outputs.
        if b_lines1 != b_lines2:
            print(f"\tTEST FAILED! {idx+1}/{num}\nExecutable is damaged.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"\tTEST PASSED! {idx+1}/{num}")
    

if __name__ == "__main__":

    test_encoding_rates()
    print("-----------------------------------------------------------")
    test_time_force()
    print("-----------------------------------------------------------")
    test_capacity_force()
    print("-----------------------------------------------------------")
    test_capacity()
    print("-----------------------------------------------------------")
    run_check()