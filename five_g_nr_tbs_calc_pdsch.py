import math

class PDSCH_TBSize_Calc:
    def __init__(self):
        self.N_re = 0
        self.N_info = 0 
        self.I_MCS = "0"            # mcs index
        self.mcs_info = (0, 0, 0)   # Qm, R, v
        self.mcs_table = "table_2"  # table_1, table_2, table_3

    ## if Table 5.1.3.1-2 is used and 0 ≤ I_MCS ≤ 27 , or a table other than Table
    ## 5.1.3.1-2 is used and 0 ≤ I_MCS ≤ 28
    def tbs_calcuate(self):
        if self.N_info <= 3824:
            # n = max(3, floor(log2(N_info)) - 6)
            # N_info_tmp = max(24, 2**n * floor(N_info/2**n))
            n = max(3, math.floor(math.log2(self.N_info)) - 6)
            N_info_tmp = max(24, 2**n * math.floor(self.N_info/2**n))
            return tbs_for_n_info_3824[n]
        else:
            # n = floor(log2(N_info - 24)) - 5
            # N_info_tmp = max(3840, 2**n * round((N_info - 24)/2**n))
            n = math.floor(math.log2(self.N_info - 24)) - 5
            N_info_tmp = max(3840, 2**n * round((self.N_info - 24)/2**n))

            if R <= 1/4:
                C = math.ceil((N_info_tmp + 24)/3816)
            elif N_info_tmp > 8424:
                C = math.ceil((N_info_tmp + 24)/8424)
            else:
                C = 1

            tbs = 8 * C * math.ceil((N_info_tmp + 24)/(8 * C)) - 24
        

    def determine_re_whin_prb(self, symb_per_slot, cdm_group_wo_data, total_prb_num):
        # N'_re = N_rb_sc * N_sh_symb -N_prb_dmrs - N_prb_oh 
        N_rb_sc = 12
        N_sh_symb = symb_per_slot
        N_prb_dmrs = 12
        N_prb_oh = 0   # range: 0, 6, 12, 18
        n_prb = total_prb_num

        if cdm_group_wo_data == 1:
            N_prb_dmrs = 12
        elif cdm_group_wo_data == 2:
            N_prb_dmrs = 6

        N_re_tmp = N_rb_sc * N_sh_symb - N_prb_dmrs - N_prb_oh 
        N_re = min(156, N_re_tmp) * n_prb

        self.N_re = N_re
        return N_re

    def get_N_info(self, code_rate, mod_order, num_layer):
        # N_info = N_re * R * Qm * v, where R: Code Rate, Qm: Modulation Order, v: number of layers
        R = code_rate
        Qm = mod_order
        v = num_layer
        N_info = self.N_re * R * Qm * v

        self.N_info = N_info
        return N_info


    def get_mcs(self, i_mcs, mod_order="qam256"):
        # if the higher layer parameter mcs-Table given by PDSCH-Config is set to 'qam256', 
        # and the PDSCH is scheduled by a PDCCH with DCI format 1_1 with CRC scrambled by C-RNTI
        #  - the UE shall use IMCS and Table 5.1.3.1-2 to determine the modulation order (Qm) 
        #    and Target code rate (R) used in the physical downlink shared channel.
        # ... ...
        # else
        # - the UE shall use IMCS and Table 5.1.3.1-1 to determine the modulation order (Qm) 
        # and Target code rate (R) used in the physical downlink shared channel.
        if mod_order == "qam256":
            mcs = pdsch_mcs_table_2[i_mcs]
            return mcs
        else:  # default: qam64
            mcs = pdsch_mcs_table_1[i_mcs]
            return mcs


## 3GPP 38.214 tables 5.1.3.1-1
pdsch_mcs_table_1 = {
    # MCS Index(I_MCS), Modulation Order(Qm), Target code Rate (R) x [1024], efficiency Spectral
    "0": (2, 120, 0.2344),
    "1": (2, 157, 0.3066),
    "2": (2, 193, 0.3770),
    "3": (2, 251, 0.4902),
    "4": (2, 308, 0.6016),
    "5": (2, 379, 0.7402),
    "6": (2, 449, 0.8770),
    "7": (2, 526, 1.0273),
    "8": (2, 602, 1.1758),
    "9": (2, 679, 1.3262),
    "10": (4, 340, 1.3281),
    "11": (4, 378, 1.4766),
    "12": (4, 434, 1.6953),
    "13": (4, 490, 1.9141),
    "14": (4, 553, 2.1602),
    "15": (4, 616, 2.4063),
    "16": (4, 658, 2.5703),
    "17": (6, 438, 2.5664),
    "18": (6, 466, 2.7305),
    "19": (6, 517, 3.0293),
    "20": (6, 567, 3.3223),
    "21": (6, 616, 3.6094),
    "22": (6, 666, 3.9023),
    "23": (6, 719, 4.2129),
    "24": (6, 772, 4.5234),
    "25": (6, 822, 4.8164),
    "26": (6, 873, 5.1152),
    "27": (6, 910, 5.3320),
    "28": (6, 948, 5.5547),
    "29": (2, "reserved"),
    "30": (4, "reserved"),
    "31": (6, "reserved"),
}

## Table 5.1.3.1-2: MCS index table 2 for PDSCH
pdsch_mcs_table_2 = {
    # MCS Index(I_MCS), Modulation Order(Qm), Target code Rate (R) x [1024] efficiency Spectral
    "0": (2, 120, 0.2344),
    "1": (2, 193, 0.3770),
    "2": (2, 308, 0.6016),
    "3": (2, 449, 0.8770),
    "4": (2, 602, 1.1758),
    "5": (4, 378, 1.4766),
    "6": (4, 434, 1.6953),
    "7": (4, 490, 1.9141),
    "8": (4, 553, 2.1602),
    "9": (4, 616, 2.4063),
    "10": (4, 658, 2.5703),
    "11": (6, 466, 2.7305),
    "12": (6, 517, 3.0293),
    "13": (6, 567, 3.3223),
    "14": (6, 616, 3.6094),
    "15": (6, 666, 3.9023),
    "16": (6, 719, 4.2129),
    "17": (6, 772, 4.5234),
    "18": (6, 822, 4.8164),
    "19": (6, 873, 5.1152),
    "20": (8, 682.5, 5.3320),
    "21": (8, 711, 5.5547),
    "22": (8, 754, 5.8906),
    "23": (8, 797, 6.2266),
    "24": (8, 841, 6.5703),
    "25": (8, 885, 6.9141),
    "26": (8, 916.5, 7.1602),
    "27": (8, 948, 7.4063),
    "28": (2, "reserved", "reserved"),
    "29": (4, "reserved", "reserved"),
    "30": (6, "reserved", "reserved"),
    "31": (8, "reserved", "reserved"),
}

## Table 5.1.3.1-3: MCS index table 3 for PDSCH
pdsch_mcs_table_3 = {
# MCS Index(I_MCS), Modulation Order(Qm), Target code Rate (R) x [1024], efficiency Spectral
    "0": (2, 30, 0.0586),
    "1": (2, 40, 0.0781),
    "2": (2, 50, 0.0977),
    "3": (2, 64, 0.1250),
    "4": (2, 78, 0.1523),
    "5": (2, 99, 0.1934),
    "6": (2, 120, 0.2344),
    "7": (2, 157, 0.3066),
    "8": (2, 193, 0.3770),
    "9": (2, 251, 0.4902),
    "10": (2, 308, 0.6016),
    "11": (2, 379, 0.7402),
    "12": (2, 449, 0.8770),
    "13": (2, 526, 1.0273),
    "14": (2, 602, 1.1758),
    "15": (4, 340, 1.3281),
    "16": (4, 378, 1.4766),
    "17": (4, 434, 1.6953),
    "18": (4, 490, 1.9141),
    "19": (4, 553, 2.1602),
    "20": (4, 616, 2.4063),
    "21": (6, 438, 2.5664),
    "22": (6, 466, 2.7305),
    "23": (6, 517, 3.0293),
    "24": (6, 567, 3.3223),
    "25": (6, 616, 3.6094),
    "26": (6, 666, 3.9023),
    "27": (6, 719, 4.2129),
    "28": (6, 772, 4.5234),
    "29": (2, "reserved", "reserved"),
    "30": (4, "reserved", "reserved"),
    "31": (6, "reserved", "reserved"),
}

## Table 5.1.3.2-1: TBS for N_info ≤ 3824
tbs_for_n_info_3824 = {
   # Index, TBS
    "1": 24,    "31": 336,   "61": 1288,   "91": 3624,
    "2": 32,    "32": 352,   "62": 1320,   "92": 3752,
    "3": 40,    "33": 368,   "63": 1352,   "93": 3824,
    "4": 48,    "34": 384,   "64": 1416,
    "5": 56,    "35": 408,   "65": 1480,
    "6": 64,    "36": 432,   "66": 1544,
    "7": 72,    "37": 456,   "67": 1608,
    "8": 80,    "38": 480,   "68": 1672,
    "9": 88,    "39": 504,   "69": 1736,
    "10": 96,   "40": 528,   "70": 1800,
    "11": 104,  "41": 552,   "71": 1864,
    "12": 112,  "42": 576,   "72": 1928,
    "13": 120,  "43": 608,   "73": 2024,
    "14": 128,  "44": 640,   "74": 2088,
    "15": 136,  "45": 672,   "75": 2152,
    "16": 144,  "46": 704,   "76": 2216,
    "17": 152,  "47": 736,   "77": 2280,
    "18": 160,  "48": 768,   "78": 2408,
    "19": 168,  "49": 808,   "79": 2472,
    "20": 176,  "50": 848,   "80": 2536,
    "21": 184,  "51": 888,   "81": 2600,
    "22": 192,  "52": 928,   "82": 2664,
    "23": 208,  "53": 984,   "83": 2728,
    "24": 224,  "54": 1032,  "84": 2792,
    "25": 240,  "55": 1064,  "85": 2856,
    "26": 256,  "56": 1128,  "86": 2976,
    "27": 272,  "57": 1160,  "87": 3104,
    "28": 288,  "58": 1192,  "88": 3240,
    "29": 304,  "59": 1224,  "89": 3368,
    "30": 320,  "60": 1256,  "90": 3496, 
}

if __name__ == "__main__":
    pass