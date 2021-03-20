import json
import random

with open('malware_results.json') as json_file:
    json_res = json.load(json_file)
    all_malware_features = json_res['all_features']
    list_of_malware_vectors = json_res['vectors']
    del json_res
    
with open('benign_results.json') as json_file:
    json_res = json.load(json_file)
    all_benign_features = json_res['all_features']
    list_of_benign_vectors = json_res['vectors']
    del json_res

i = 0
print("Num of benign features: " + str(len(all_benign_features)))
print("Num of malware features: " + str(len(all_malware_features)))
while i < len(all_malware_features) and i < len(all_benign_features):
    if all_malware_features[i] != all_benign_features[i]:
        feature = all_malware_features[i]
        if feature in all_benign_features:
            pos = all_benign_features.index(feature)
            all_benign_features.insert(i, all_benign_features.pop(pos))
            print(str(i) + ". Common feature: " + feature)
            
            j = 0
            while j < len(list_of_benign_vectors):
                list_of_benign_vectors[j].insert(i, list_of_benign_vectors[j].pop(pos))
                j += 1
        elif feature.isupper():
            all_benign_features.insert(i, feature)
            
            j = 0
            while j < len(list_of_benign_vectors):
                list_of_benign_vectors[j].insert(i, 0)
                j += 1
        else:
            j = 0
            while j < len(list_of_malware_vectors):
                list_of_malware_vectors[j].pop(i)
                j += 1
            print(str(i) + ". Removed: " + all_malware_features.pop(i))
            i -= 1
    i += 1

print("Num of benign + malware features: " + str(len(all_benign_features)))

if i == len(all_malware_features):
    while i < len(all_benign_features):
        feature = all_benign_features[i]
        if feature.isupper():
            print(str(i) + ". BENIGN Appended: " + feature)
            all_malware_features.append(feature)
            j = 0
            while j < len(list_of_malware_vectors):
                list_of_malware_vectors[j].append(0)
                j += 1
        else:
            j = 0
            while j < len(list_of_benign_vectors):
                list_of_benign_vectors[j].pop(i)
                j += 1
            print(str(i) + ". BENIGN Removed: " + all_benign_features.pop(i))
            i -= 1
        i += 1
else:
    while i < len(all_malware_features):
        feature = all_malware_features[i]
        if feature.isupper():
            print(str(i) + ". MALWARE Appended: " + feature)
            all_benign_features.append(feature)
            j = 0
            while j < len(list_of_benign_vectors):
                list_of_benign_vectors[j].append(0)
                j += 1
        else:
            j = 0
            while j < len(list_of_malware_vectors):
                list_of_malware_vectors[j].pop(i)
                j += 1
            print(str(i) + ". MALWARE Removed: " + all_malware_features.pop(i))
            i -= 1
        i += 1
    
print("All features was processed...")
list_of_vectors = []
results = []
if all_benign_features == all_malware_features and len(all_benign_features) == len(list_of_benign_vectors[0]) \
        and len(all_benign_features) == len(list_of_malware_vectors[0]):
    print("Features are equal. Num of benign and malware features: " + str(len(all_benign_features)))
    json_res = {'all_features': all_benign_features}

    while True:
        vector = []
        if random.random() > 0.5 and len(list_of_benign_vectors) != 0:
            vector = list_of_benign_vectors.pop(random.randint(1, len(list_of_benign_vectors)) - 1)
            results.append(1.0)
            if len(list_of_benign_vectors) % 100 == 0:
                print("Num of benign vectors: " + str(len(list_of_benign_vectors)))
                print("Num of processed vectors: " + str(len(results)))
        elif len(list_of_malware_vectors) != 0:
            vector = list_of_malware_vectors.pop(random.randint(1, len(list_of_malware_vectors)) - 1)
            results.append(-1.0)
            if len(list_of_malware_vectors) % 100 == 0:
                print("Num of malware vectors: " + str(len(list_of_malware_vectors)))
                print("Num of processed vectors: " + str(len(results)))
        elif len(list_of_benign_vectors) != 0:
            vector = list_of_benign_vectors.pop(random.randint(1, len(list_of_benign_vectors)) - 1)
            results.append(1.0)
            if len(list_of_benign_vectors) % 100 == 0:
                print("Num of benign vectors: " + str(len(list_of_benign_vectors)))
                print("Num of processed vectors: " + str(len(results)))
        else:
            break
        list_of_vectors.append(vector)
        del vector
    
    json_res['vectors'] = list_of_vectors
    json_res['results'] = results
    json_res['stage'] = 'malware'
    json_res['num'] = len(list_of_vectors)
    with open('results.json', 'w') as outfile:
        json.dump(json_res, outfile)
else:
    print("Something went wrong!")
    print("Num of benign features: " + str(len(all_benign_features)))
    print("Num of malware features: " + str(len(all_malware_features)))
    print("Len of benign vector: " + str(len(list_of_benign_vectors[0])))
    print("Len of malware vector: " + str(len(list_of_malware_vectors[0])))
