#!/usr/bin/env python3

"""Search for known bad hashes among hashes collected from multiple systems"""


import argparse
from pathlib import Path
from contextlib import closing


__author__ = "Jordan Linden"
__version__ = "1.0"
__status__ = "Prototype"


def parse_args():
    parser = argparse.ArgumentParser(
        prog='search-hashes.py',
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # temporarily remove the optional arguments section
    parser_opt = parser._action_groups.pop()
    
    parser_req = parser.add_argument_group("required arguments (either/or)")
    
    parser_req_group = parser_req.add_mutually_exclusive_group(required=True)
    parser_req_group.add_argument(
        '--hash',
        metavar='<string>',
        default=argparse.SUPPRESS,
        help='a single known bad hash to search for'
    )
    parser_req_group.add_argument(
        '--hashes',
        metavar='<file path>',
        type=argparse.FileType("r"),
        default=argparse.SUPPRESS,
        help='path to a text file containing multiple known bad hashes'
    )
    
    # reinsert the optional arguments section
    parser._action_groups.append(parser_opt)
    
    parser.add_argument(
        '--format',
        choices=['by_file', 'by_hash'],
        default='by_file',
        help='how to organize results in the generated report'
    )
    
    parser.add_argument(
        'directory',
        type=Path,
        help='directory location of text files each containing hashes collected from a system'
    )
    
    parser.add_argument("-v", "--version", action="version", version='%(prog)s ' + __version__)
    
    return parser, parser.parse_args()


def get_bad_hashes(hash, hashes):
    hash_list = []
    
    if hashes:
        with closing(hashes):
            for line in hashes:
                if line.strip() not in hash_list:
                    hash_list.append(line.strip())
    else:
        hash_list.append(hash)
    
    return hash_list


def search(bad_hashes, directory):
    result_dict = {}
    no_matches = bad_hashes.copy()
    
    for obj in directory.iterdir():
        if obj.is_file():
            with obj.open() as file:
                hash_list = [hash.strip() for hash in file.readlines()]
            
            matches = []
            for hash in hash_list:
                if hash in bad_hashes:
                    matches.append(hash)
                    
                    if hash in no_matches:
                        no_matches.remove(hash)
        
        result_dict[obj.name] = matches
    
    return result_dict, no_matches


def get_report_by_file(result_dict):
    report = []
    for file,hashes in sorted(result_dict.items(), key=lambda x: len(x[1]), reverse=True):
        if len(hashes) > 0:
            text = "hash" if len(hashes) == 1 else "hashes"
            report.append(f'{len(hashes)} {text} found in {file}:')
            
            for hash in hashes:
                report.append(' '*4 + hash)
            
            report.append('\n')
        else:
            report.append(f'None found in {file}')
    
    return report


def get_report_by_hash(result_dict):
    new_dict = {}
    for file,hashes in result_dict.items():
        for hash in hashes:
            if hash not in new_dict:
                new_dict[hash] = [file]
            else:
                new_dict[hash].append(file)
    
    report = []
    for hash,files in sorted(new_dict.items(), key=lambda x: len(x[1]), reverse=True):
        if len(files) > 0:
            text = "file" if len(files) == 1 else "files"
            report.append(f'Hash {hash} found in {len(files)} {text}:')
            
            for file in files:
                report.append(' '*4 + file)
            
            report.append('\n')
    
    return report


def main():
    parser, args = parse_args()
    
    directory = args.directory
    if not directory.is_dir():
        parser.error("directory path is invalid or not found")
    if not any(directory.iterdir()):
        parser.error("directory is empty")
    
    hash = args.hash if hasattr(args, "hash") else None
    hashes = args.hashes if hasattr(args, "hashes") else None
    
    bad_hashes = get_bad_hashes(hash, hashes)
    
    result_dict, no_matches = search(bad_hashes, directory)
    
    report = globals()['get_report_' + args.format](result_dict)
    
    for line in report:
        print(line)
    
    if len(no_matches) > 0:
        print('\n')
        for hash in no_matches:
            print(f'Hash {hash} not found')
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
