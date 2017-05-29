import sys


def is_py35_or_higher():
    version = sys.version_info
    return version[0] >= 3 and version[1] >= 5


def merge_dicts(dict1, dict2):
    """
    Takes two dictionaries and merges them together.

    Note: If a duplicate key exists in dict2 the value of the key in dict2 will be used i.e. The value dict1 will be
    overwritten.

    Accurate/Idiomatic Reference: http://treyhunner.com/2016/02/how-to-merge-dictionaries-in-python/
    Performance Reference: https://gist.github.com/treyhunner/f35292e676efa0be1728

    Uses dictionary unpacking for python versions greater than or equal to 3.5.
    Performance: 27ms
    Accurate: Yes
    Idiomatic: Yes

    Uses dictionary comprehension solutions for python versions less than 3.5.
    Performance: 45ms
    Accurate: Yes
    Idiomatic: Not really.

    :param dict1: A python dictionary
    :param dict2: A python dictionary
    :return: The union of dict1 and dict2.
    """
    if type(dict1) is type(dict2) is dict:
        if is_py35_or_higher():
            return {**dict1, **dict2}
        else:
            return {k: v for d in [dict1, dict2] for k, v in d.items()}
    else:
        raise TypeError('In merge_dicts(), both input parameters dict1 and dict2 must be of type dict.')
