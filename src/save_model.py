"""
Modules to locally save pretrained hugging face models
"""
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "bigscience/bloom-560m"

tokenizer = AutoTokenizer.from_pretrained(MODEL)
model = AutoModelForCausalLM.from_pretrained(MODEL)

model.save_pretrained("enclave/bloom")
tokenizer.save_pretrained("enclave/bloom")

print("Pretrained model and tokenizer saved successfully.")
