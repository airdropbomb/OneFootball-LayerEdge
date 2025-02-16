USERagent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

query_verify = "mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}"

query_campaign = 'fragment ActivityFields on CampaignActivity {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverAssetUrl\n  type\n  identityType\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  records {\n    id\n    status\n    createdAt\n    activityId\n    properties\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  tags {\n    id\n    name\n    __typename\n  }\n  reward {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    __typename\n  }\n  targetReward {\n    id\n    activityId\n    missionId\n    __typename\n  }\n  nft {\n    id\n    tokenId\n    name\n    description\n    image\n    properties\n    mintPrice\n    platformFee\n    maxSupply\n    maxMintCountPerAddress\n    nftContract {\n      id\n      address\n      type\n      chainId\n      __typename\n    }\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nquery CampaignActivities($campaignId: String!) {\n  campaign(id: $campaignId) {\n    id\n    activities {\n      ...ActivityFields\n      __typename\n    }\n    __typename\n  }\n}'

query_login = 'mutation UserLogin($data: UserLoginInput!) {\n  userLogin(data: $data)\n}'
query_login_activities_panel = 'query CampaignSpotByCampaignIdAndReferralCode($campaignId: String!, $referralCode: String!) {\n  campaignSpotByCampaignIdAndReferralCode(\n    campaignId: $campaignId\n    referralCode: $referralCode\n  ) {\n    referralCode\n    __typename\n  }\n}'

query_deil = 'fragment ActivityFields on CampaignActivity {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverAssetUrl\n  type\n  identityType\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  records {\n    id\n    status\n    createdAt\n    activityId\n    properties\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  tags {\n    id\n    name\n    __typename\n  }\n  reward {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    __typename\n  }\n  targetReward {\n    id\n    activityId\n    missionId\n    __typename\n  }\n  nft {\n    id\n    tokenId\n    name\n    description\n    image\n    properties\n    mintPrice\n    platformFee\n    maxSupply\n    maxMintCountPerAddress\n    nftContract {\n      id\n      address\n      type\n      chainId\n      __typename\n    }\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nfragment MissionFields on CampaignMission {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverPhotoUrl\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  tags {\n    id\n    name\n    __typename\n  }\n  rewards {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    awardMechanism\n    __typename\n  }\n  records {\n    id\n    status\n    createdAt\n    missionId\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  activities {\n    id\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nfragment CampaignCommunityGoalFields on CampaignCommunityGoal {\n  id\n  title\n  description\n  additionalDetails\n  imageUrl\n  threshold\n  status\n  startDateTimeAt\n  endDateTimeAt\n  createdAt\n  updatedAt\n  isThresholdHidden\n  isHidden\n  ctaButtonCopy\n  ctaButtonUrl\n  __typename\n}\n\nquery CampaignActivitiesPanel($campaignId: String!) {\n  campaign(id: $campaignId) {\n    activities {\n      ...ActivityFields\n      __typename\n    }\n    missions {\n      ...MissionFields\n      __typename\n    }\n    communityGoals {\n      ...CampaignCommunityGoalFields\n      activity {\n        ...ActivityFields\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}'

query_verify_deil = 'mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}'

query_quiz = 'fragment ActivityFields on CampaignActivity {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverAssetUrl\n  type\n  identityType\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  records {\n    id\n    status\n    createdAt\n    activityId\n    properties\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  tags {\n    id\n    name\n    __typename\n  }\n  reward {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    __typename\n  }\n  targetReward {\n    id\n    activityId\n    missionId\n    __typename\n  }\n  nft {\n    id\n    tokenId\n    name\n    description\n    image\n    properties\n    mintPrice\n    platformFee\n    maxSupply\n    maxMintCountPerAddress\n    nftContract {\n      id\n      address\n      type\n      chainId\n      __typename\n    }\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nfragment CampaignFields on Campaign {\n  id\n  name\n  isDisabled\n  description\n  logoUrl\n  coverPhotoUrl\n  customLinkPreviewUrl\n  faviconUrl\n  bannerLogoUrl\n  bannerText\n  brandColor\n  showRanking\n  mandatoryIdentities\n  pointName\n  pointEmoji\n  showPoints\n  tabListOverride\n  tagSectionNameOverride\n  showAllTag\n  showSectionHeader\n  showLogo\n  standaloneActivities {\n    id\n    __typename\n  }\n  tags {\n    id\n    name\n    imageUrl\n    childTags {\n      id\n      name\n      imageUrl\n      bannerImageUrl\n      createdAt\n      updatedAt\n      __typename\n    }\n    createdAt\n    updatedAt\n    __typename\n  }\n  customURLConfig {\n    id\n    slug\n    domain {\n      id\n      type\n      domain\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment MissionFields on CampaignMission {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverPhotoUrl\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  tags {\n    id\n    name\n    __typename\n  }\n  rewards {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    awardMechanism\n    __typename\n  }\n  records {\n    id\n    status\n    createdAt\n    missionId\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  activities {\n    id\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nquery ActivityQuizDetail($activityId: String!) {\n  activity(id: $activityId) {\n    campaign {\n      ...CampaignFields\n      __typename\n    }\n    mission {\n      ...MissionFields\n      __typename\n    }\n    ...ActivityFields\n    __typename\n  }\n}'
query_quiz_verify = 'mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}'
query_user_me = 'fragment RecordFields on CampaignSpot {\n  records {\n    id\n    status\n    properties\n    points\n    instanceCount\n    createdAt\n    updatedAt\n    activityId\n    activity {\n      id\n      title\n      description\n      type\n      __typename\n    }\n    mission {\n      id\n      title\n      description\n      __typename\n    }\n    communityGoal {\n      id\n      title\n      description\n      threshold\n      __typename\n    }\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nquery UserMe($campaignId: String!) {\n  userMe {\n    id\n    campaignSpot(campaignId: $campaignId) {\n      id\n      points\n      referralCode\n      referralCodeEditsRemaining\n      ...RecordFields\n      __typename\n    }\n    __typename\n  }\n}'
query_quiz2 = 'fragment ActivityFields on CampaignActivity {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverAssetUrl\n  type\n  identityType\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  records {\n    id\n    status\n    createdAt\n    activityId\n    properties\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  tags {\n    id\n    name\n    __typename\n  }\n  reward {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    __typename\n  }\n  targetReward {\n    id\n    activityId\n    missionId\n    __typename\n  }\n  nft {\n    id\n    tokenId\n    name\n    description\n    image\n    properties\n    mintPrice\n    platformFee\n    maxSupply\n    maxMintCountPerAddress\n    nftContract {\n      id\n      address\n      type\n      chainId\n      __typename\n    }\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nfragment CampaignFields on Campaign {\n  id\n  name\n  isDisabled\n  description\n  logoUrl\n  coverPhotoUrl\n  customLinkPreviewUrl\n  faviconUrl\n  bannerLogoUrl\n  bannerText\n  brandColor\n  showRanking\n  mandatoryIdentities\n  pointName\n  pointEmoji\n  showPoints\n  tabListOverride\n  tagSectionNameOverride\n  showAllTag\n  showSectionHeader\n  showLogo\n  standaloneActivities {\n    id\n    __typename\n  }\n  tags {\n    id\n    name\n    imageUrl\n    childTags {\n      id\n      name\n      imageUrl\n      bannerImageUrl\n      createdAt\n      updatedAt\n      __typename\n    }\n    createdAt\n    updatedAt\n    __typename\n  }\n  customURLConfig {\n    id\n    slug\n    domain {\n      id\n      type\n      domain\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment MissionFields on CampaignMission {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverPhotoUrl\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  tags {\n    id\n    name\n    __typename\n  }\n  rewards {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    awardMechanism\n    __typename\n  }\n  records {\n    id\n    status\n    createdAt\n    missionId\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  activities {\n    id\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nquery ActivityQuizDetail($activityId: String!) {\n  activity(id: $activityId) {\n    campaign {\n      ...CampaignFields\n      __typename\n    }\n    mission {\n      ...MissionFields\n      __typename\n    }\n    ...ActivityFields\n    __typename\n  }\n}'
COMMON_HEADERS = {
    'accept': '*/*',
    'accept-language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
    'content-type': 'application/json',
    'origin': 'https://ofc.onefootball.com',
    'priority': 'u=1, i',
    'referer': 'https://ofc.onefootball.com/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': USERagent,
}
json_data_qz1 = {
        'operationName': 'ActivityQuizDetail',
        'variables': {
            'activityId': 'd05d17cb-9ecd-404e-850e-f7d92b895bb4',
        },
        'query': query_quiz,
    }

json_data_qz2 = {
        'operationName': 'ActivityQuizDetail',
        'variables': {
            'activityId': 'b5df53a7-1777-4fb4-b334-b2bfc23f1993',
        },
        'query': query_quiz,
    }
json_data_qz3 = {
    'operationName': 'ActivityQuizDetail',
    'variables': {
        'activityId': 'f9df435c-cdab-4992-af97-cb8f37e00f13',
        'isTrusted': True,
    },
    'query': 'fragment ActivityFields on CampaignActivity {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverAssetUrl\n  type\n  identityType\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  records {\n    id\n    status\n    createdAt\n    activityId\n    properties\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  tags {\n    id\n    name\n    __typename\n  }\n  reward {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    __typename\n  }\n  targetReward {\n    id\n    activityId\n    missionId\n    __typename\n  }\n  nft {\n    id\n    tokenId\n    name\n    description\n    image\n    properties\n    mintPrice\n    platformFee\n    maxSupply\n    maxMintCountPerAddress\n    nftContract {\n      id\n      address\n      type\n      chainId\n      __typename\n    }\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nfragment CampaignFields on Campaign {\n  id\n  name\n  isDisabled\n  description\n  logoUrl\n  coverPhotoUrl\n  customLinkPreviewUrl\n  faviconUrl\n  bannerLogoUrl\n  bannerText\n  brandColor\n  showRanking\n  mandatoryIdentities\n  pointName\n  pointEmoji\n  showPoints\n  tabListOverride\n  tagSectionNameOverride\n  showAllTag\n  showSectionHeader\n  showLogo\n  standaloneActivities {\n    id\n    __typename\n  }\n  tags {\n    id\n    name\n    imageUrl\n    childTags {\n      id\n      name\n      imageUrl\n      bannerImageUrl\n      createdAt\n      updatedAt\n      __typename\n    }\n    createdAt\n    updatedAt\n    __typename\n  }\n  customURLConfig {\n    id\n    slug\n    domain {\n      id\n      type\n      domain\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment MissionFields on CampaignMission {\n  id\n  createdAt\n  updatedAt\n  startDateTimeAt\n  endDateTimeAt\n  title\n  description\n  coverPhotoUrl\n  recurringPeriod {\n    count\n    type\n    __typename\n  }\n  recurringMaxCount\n  properties\n  tags {\n    id\n    name\n    __typename\n  }\n  rewards {\n    id\n    title\n    description\n    quantity\n    type\n    imageUrl\n    properties\n    awardMechanism\n    __typename\n  }\n  records {\n    id\n    status\n    createdAt\n    missionId\n    rewardRecords {\n      id\n      status\n      appliedRewardType\n      appliedRewardQuantity\n      appliedRewardMetadata\n      error\n      rewardId\n      reward {\n        id\n        quantity\n        type\n        properties\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  activities {\n    id\n    __typename\n  }\n  isHidden\n  __typename\n}\n\nquery ActivityQuizDetail($activityId: String!) {\n  activity(id: $activityId) {\n    campaign {\n      ...CampaignFields\n      __typename\n    }\n    mission {\n      ...MissionFields\n      __typename\n    }\n    ...ActivityFields\n    __typename\n  }\n}',
}

json_data_qz4 = {
        'operationName': 'ActivityQuizDetail',
        'variables': {
            'activityId': '09f14492-1706-4d15-8fa8-babf687f6c3e',
            'isTrusted': True,
        },
        'query': query_quiz,
    }

json_data_qz_2 = {
    'operationName': 'VerifyActivity',
    'variables': {
        'data': {
            'activityId': 'b5df53a7-1777-4fb4-b334-b2bfc23f1993',
            'metadata': {
                'responses': [
                    {
                        'questionId': 'q1',
                        'answers': [
                            {
                                'id': 'b',
                                'text': '',
                            },
                        ],
                    },
                    {
                        'questionId': 'q2',
                        'answers': [
                            {
                                'id': 'd',
                                'text': '',
                            },
                        ],
                    },
                ],
            },
        },
    },
    'query': 'mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}',
}

json_data_qz_1 = {
        'operationName': 'VerifyActivity',
        'variables': {
            'data': {
                'activityId': 'd05d17cb-9ecd-404e-850e-f7d92b895bb4',
                'metadata': {
                    'responses': [
                        {
                            'questionId': 'q1',
                            'answers': [
                                {
                                    'id': 'a',
                                    'text': '',
                                },
                            ],
                        },
                        {
                            'questionId': 'q2',
                            'answers': [
                                {
                                    'id': 'd',
                                    'text': '',
                                },
                            ],
                        },
                        {
                            'questionId': 'q3',
                            'answers': [
                                {
                                    'id': 'd',
                                    'text': '',
                                },
                            ],
                        },
                    ],
                },
            },
        },
        'query': query_quiz_verify,
    }


json_data_3 = {
    'operationName': 'VerifyActivity',
    'variables': {
        'data': {
            'activityId': 'f9df435c-cdab-4992-af97-cb8f37e00f13',
            'metadata': {
                'responses': [
                    {
                        'questionId': 'q1',
                        'answers': [
                            {
                                'id': 'd',
                                'text': '',
                            },
                        ],
                    },
                ],
            },
        },
    },
    'query': 'mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}',
}

json_data_4 = {
    'operationName': 'VerifyActivity',
    'variables': {
        'data': {
            'activityId': '09f14492-1706-4d15-8fa8-babf687f6c3e',
            'metadata': {
                'responses': [
                    {
                        'questionId': 'q2',
                        'answers': [
                            {
                                'id': 'd',
                                'text': '',
                            },
                        ],
                    },
                ],
            },
        },
    },
    'query': 'mutation VerifyActivity($data: VerifyActivityInput!) {\n  verifyActivity(data: $data) {\n    record {\n      id\n      activityId\n      status\n      properties\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    missionRecord {\n      id\n      missionId\n      status\n      createdAt\n      rewardRecords {\n        id\n        status\n        appliedRewardType\n        appliedRewardQuantity\n        appliedRewardMetadata\n        error\n        rewardId\n        reward {\n          id\n          quantity\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}',
}







