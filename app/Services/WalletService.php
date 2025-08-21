<?php

namespace App\Services;

use App\Enums\TransactionName;
use App\Enums\DigitTransactionName;
use App\Enums\TransactionType;
use App\Models\User;
use Bavix\Wallet\External\Dto\Extra;
use Bavix\Wallet\External\Dto\Option;

class WalletService
{
    public function forceTransfer(User $from, User $to, float $amount, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        return $from->forceTransferFloat($to, $amount, new Extra(
            deposit: new Option(self::buildTransferMeta($to, $from, $transaction_name, $meta)),
            withdraw: new Option(self::buildTransferMeta($from, $to, $transaction_name, $meta))
        ));
    }

    public function transfer(User $from, User $to, float $amount, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        return $from->forceTransferFloat($to, $amount, new Extra(
            deposit: new Option(self::buildTransferMeta($to, $from, $transaction_name, $meta)),
            withdraw: new Option(self::buildTransferMeta($from, $to, $transaction_name, $meta))
        ));
    }

    public function deposit(User $user, float $amount, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        $user->depositFloat($amount, self::buildDepositMeta($user, $user, $transaction_name, $meta));
    }

    public function withdraw(User $user, float $amount, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        try {
            \Log::info("Attempting to withdraw {$amount} from user {$user->id} for transaction: {$transaction_name->value}");
            \Log::info("User balance before withdrawal: {$user->balanceFloat}");
            
            $result = $user->withdrawFloat($amount, self::buildWithdrawMeta($user, $user, $transaction_name, $meta));
            
            \Log::info("Withdrawal successful. User balance after withdrawal: {$user->balanceFloat}");
            
            return $result;
        } catch (\Exception $e) {
            \Log::error("Withdrawal failed for user {$user->id}: " . $e->getMessage(), [
                'amount' => $amount,
                'transaction_name' => $transaction_name->value,
                'meta' => $meta,
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    public static function buildTransferMeta(User $user, User $target_user, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        return array_merge([
            'name' => $transaction_name,
            'opening_balance' => $user->balanceFloat,
            'target_user_id' => $target_user->id,
        ], $meta);
    }

    public static function buildDepositMeta(User $user, User $target_user, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        return array_merge([
            'name' => $transaction_name->value,
            'opening_balance' => $user->balanceFloat,
            'target_user_id' => $target_user->id,
        ], $meta);
    }

    public static function buildWithdrawMeta(User $user, User $target_user, TransactionName|DigitTransactionName $transaction_name, array $meta = [])
    {
        return array_merge([
            'name' => $transaction_name->value,
            'opening_balance' => $user->balanceFloat,
            'target_user_id' => $target_user->id,
        ], $meta);
    }
}
