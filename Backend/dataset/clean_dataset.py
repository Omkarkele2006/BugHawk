
from datasets import load_dataset,Dataset,load_from_disk,DatasetDict,ClassLabel
import pandas as pd

# ds = load_dataset("Addyk24/code_maintainence")
# ds_1 = load_dataset("Muennighoff/quixbugs")
# ds_2 = load_dataset("DetectVul/devign")
# ds_3 = load_dataset("google-research-datasets/mbpp")

# ds_4 = pd.read_csv("dataset/code_vulnerabilities.csv")

# ds_5 = pd.read_csv("dataset/some_more_debug.csv")

# ds_5["problem"] = ds_5["Title"] + " : " + ds_5["Body"]


# ds_1 = pd.read_csv("dataset/threat_debug_100k_detailed.csv")
ds_1 = pd.read_csv("dataset/threat_debug_100k.csv")
ds_2 = pd.read_csv("dataset/threat_debug_dataset.csv")


def clean_dataset():
        """ Making and cleaning of Dataset """


        ds = pd.concat([ds_1,ds_2],ignore_index=True)

        return ds 


# print("DS1:",ds_1)
# print("DS2:",ds_2)
ds = clean_dataset()

ds.drop("category",axis=1,inplace=True)

# print("DS: ",ds)
print("DS TYPE : ",type(ds))
# Count how many of each label
print("Label counts: ",ds["labels"].value_counts())
label_feature = ClassLabel(names=["debug", "threat"])

# # Cast the label column
# ds = ds.cast_column("label", label_feature)

ds_shuffled = ds.sample(frac=1,random_state=42).reset_index(drop=True)

print("Shuffled ds: ",ds_shuffled)
# ds_shuffled = ds_shuffled.train_test_split(
#     test_size = 0.2,
#     stratify_by_column="label",
#     seed=0
# )
ds_shuffled.to_csv("dataset/final_code_maintainence.csv",index=False)

hf_ds = Dataset.from_pandas(ds_shuffled,preserve_index=False)
print("HF DATASET: ",hf_ds)

hf_ds = hf_ds.cast_column("labels", label_feature)

# hf_ds.save_to_disk("code_maintainece_dataset")

# hf_ds = DatasetDict({"data": hf_ds})

# print("Data Dict: ",ds_shuffled)

# hf_ds.push_to_hub("Addyk24/code_maintainence")
hf_ds.push_to_hub("Addyk24/code_threat_maintance")

# ds.push_to_hub()
# print("Main Dataset: ",ds)
# print("Dataset type: ",type(ds))


