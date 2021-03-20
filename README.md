# APK datasets for machine learning

This repository contains 3 datasets:
1. Benign apps (5642 samples from CICAndMal2017 repository)
2. Malware apps (8744 samples from VirusShare_2016 repository)
3. Their union

## JSON format

```
{
  all_features: [],
  vectors: [[]],
  results: [],
  num: int
}
```

1. *all_features* - list of APK's features (permissions, libraries, content providers and receivers)
2. *vectors* - list of binary vectors; each vector is associated with a specific APK: if *i*th element of *all_features* is contained in APK, then *i*th element of vector has a value of 1, otherwise - 0
3. *results* - list of classification; if APK, assotiated with *i*th vector, is benign, then *i*th element of *results* has a value of 1, otherwise - -1
4. *num* - the number of examples in the dataset

## Combined dataset

The combined dataset has the same format, but has a features in content:
1. Excluded all features that occur only once, except for those that have all upper-case letters (these are mostly permissions)
2. Vectors of malicious and benign apps are randomly distributed

The script for datasets combining is located in [dataset_concat.py](../blob/master/datasets_combine.py)

**Work done with the support of SPbPU, Cybersecurity and Protection of Information Institute**
