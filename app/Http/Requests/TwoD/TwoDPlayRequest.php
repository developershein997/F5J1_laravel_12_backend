<?php

namespace App\Http\Requests\TwoD;

use Illuminate\Foundation\Http\FormRequest;

class TwoDPlayRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true; // Set to true if authorization is handled by middleware
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'totalAmount' => 'required|numeric|min:1',
            'amounts' => 'required|array|min:1',
            'amounts.*.num' => 'required|string|regex:/^[0-9]{1,2}$/', // Ensure 'num' is treated as string for '00' to '99'
            'amounts.*.amount' => 'required|integer|min:1',
        ];
    }

    /**
     * Configure the validator instance.
     *
     * @param  \Illuminate\Validation\Validator  $validator
     * @return void
     */
    public function withValidator($validator)
    {
        $validator->after(function ($validator) {
            $totalAmount = $this->input('totalAmount');
            $amounts = $this->input('amounts');
            
            if (is_array($amounts)) {
                $calculatedTotal = collect($amounts)->sum('amount');
                
                if ($calculatedTotal != $totalAmount) {
                    $validator->errors()->add('totalAmount', "Total amount ({$totalAmount}) does not match the sum of individual amounts ({$calculatedTotal}).");
                }
            }
        });
    }

    /**
     * Get custom messages for validator errors.
     *
     * @return array
     */
    public function messages(): array
    {
        return [
            'totalAmount.required' => 'Total amount is required.',
            'totalAmount.numeric' => 'Total amount must be a number.',
            'totalAmount.min' => 'Total amount must be at least 1.',
            'amounts.required' => 'Bet amounts are required.',
            'amounts.array' => 'Bet amounts must be an array.',
            'amounts.min' => 'At least one bet amount is required.',
            'amounts.*.num.required' => 'Bet number is required.',
            'amounts.*.num.string' => 'Bet number must be a string.',
            'amounts.*.num.regex' => 'Bet number must be a valid 2-digit number (00-99).',
            'amounts.*.amount.required' => 'Bet amount is required.',
            'amounts.*.amount.integer' => 'Bet amount must be a whole number.',
            'amounts.*.amount.min' => 'Bet amount must be at least 1.',
        ];
    }
}
